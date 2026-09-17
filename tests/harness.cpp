// Route Provenance - test harness implementation.
//
// Bounded waits fail explicitly; no test timeout is configured anywhere. Child processes are
// assigned to a job object with kill-on-close so a failing test cannot leak a process.
#include "harness.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#error "the rp_test harness implements real process control on Windows only"
#endif

#include "route_provenance/enums.hpp"

namespace rp_test {
namespace {

struct TestCase {
  std::string suite;
  std::string name;
  TestFn fn = nullptr;
};

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

std::vector<std::string>& current_failures() {
  static std::vector<std::string> failures;
  return failures;
}

[[nodiscard]] std::string narrow(const std::wstring& text) {
  if (text.empty()) {
    return std::string{};
  }
  const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                       nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(size), '\0');
  static_cast<void>(WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                        out.data(), size, nullptr, nullptr));
  return out;
}

[[nodiscard]] std::wstring widen(const std::string& text) {
  if (text.empty()) {
    return std::wstring{};
  }
  const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                       nullptr, 0);
  std::wstring out(static_cast<std::size_t>(size), L'\0');
  static_cast<void>(MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                        out.data(), size));
  return out;
}

/// Command line quoting for CreateProcessW: arguments containing spaces, tabs or quotes are
/// wrapped in double quotes with embedded quotes doubled and backslash runs before a closing
/// quote doubled.
[[nodiscard]] std::wstring quote_argument(const std::wstring& argument) {
  if (!argument.empty() && argument.find_first_of(L" \t\"") == std::wstring::npos) {
    return argument;
  }
  std::wstring out = L"\"";
  std::size_t backslashes = 0;
  for (const wchar_t ch : argument) {
    if (ch == L'\\') {
      ++backslashes;
      continue;
    }
    if (ch == L'"') {
      out.append(backslashes * 2 + 1, L'\\');
      backslashes = 0;
      out.push_back(L'"');
      continue;
    }
    out.append(backslashes, L'\\');
    backslashes = 0;
    out.push_back(ch);
  }
  out.append(backslashes * 2, L'\\');
  out.push_back(L'"');
  return out;
}

class Handle {
 public:
  Handle() = default;
  explicit Handle(HANDLE handle) : handle_(handle) {}
  ~Handle() { reset(); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      reset();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  void reset(HANDLE handle = nullptr) {
    if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
      static_cast<void>(CloseHandle(handle_));
    }
    handle_ = handle;
  }
  [[nodiscard]] HANDLE get() const noexcept { return handle_; }
  [[nodiscard]] explicit operator bool() const noexcept {
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE handle_ = nullptr;
};

[[nodiscard]] unsigned long wait_for(HANDLE handle, unsigned milliseconds) {
  return WaitForSingleObject(handle, milliseconds);
}

}  // namespace

void register_test(const char* suite, const char* name, TestFn fn) {
  registry().push_back(TestCase{suite, name, fn});
}

Registrar::Registrar(const char* suite, const char* name, TestFn fn) { register_test(suite, name, fn); }

void report_failure(const char* file, int line, const std::string& message) {
  std::ostringstream stream;
  stream << file << ":" << line << " " << message;
  current_failures().push_back(stream.str());
}

bool current_test_failed() { return !current_failures().empty(); }

std::string describe(const char* value) { return std::string(value); }
std::string describe(char* value) { return std::string(value); }

int run_all(int argc, char** argv) {
  std::string suite_filter;
  std::string test_filter;
  bool list_only = false;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--suite" && i + 1 < argc) {
      suite_filter = argv[++i];
    } else if (arg == "--test" && i + 1 < argc) {
      test_filter = argv[++i];
    } else if (arg == "--list") {
      list_only = true;
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "usage: --suite <name> | --test <name> | --list\n";
      return 0;
    }
  }
  if (list_only) {
    for (const TestCase& test : registry()) {
      std::cout << test.suite << "." << test.name << "\n";
    }
    return 0;
  }

  std::size_t total = 0;
  std::size_t passed = 0;
  std::size_t failed = 0;
  std::size_t failure_count = 0;
  for (const TestCase& test : registry()) {
    if (!suite_filter.empty() && test.suite != suite_filter) {
      continue;
    }
    if (!test_filter.empty() && test.name != test_filter) {
      continue;
    }
    ++total;
    current_failures().clear();
    try {
      test.fn();
    } catch (const TestAborted&) {
      // The failure has already been recorded.
    } catch (const std::exception& error) {
      report_failure(__FILE__, __LINE__, std::string("unexpected exception: ") + error.what());
    } catch (...) {
      report_failure(__FILE__, __LINE__, "unexpected non-standard exception");
    }
    const bool ok = current_failures().empty();
    std::cout << "suite=" << test.suite << " test=" << test.name
              << " status=" << (ok ? "PASS" : "FAIL")
              << " failures=" << current_failures().size() << "\n";
    for (const std::string& failure : current_failures()) {
      std::cout << "FAIL " << test.suite << "." << test.name << " " << failure << "\n";
      ++failure_count;
    }
    if (ok) {
      ++passed;
    } else {
      ++failed;
    }
    std::cout.flush();
  }
  std::cout << "tests=" << total << " passed=" << passed << " failed=" << failed
            << " failures=" << failure_count << "\n";
  std::cout.flush();
  if (total == 0) {
    std::cout << "no tests matched the filter\n";
    return 1;
  }
  return failed == 0 ? 0 : 1;
}

struct ChildProcess::Impl {
  Handle process;
  Handle job;
  Handle stdin_write;
  std::string capture_path;
  unsigned long exit_code = 0;
  bool exited = false;
  std::uint32_t pid = 0;
};

ChildProcess::~ChildProcess() {
  if (impl_ != nullptr) {
    if (!impl_->exited && impl_->process) {
      terminate();
    }
    delete impl_;
    impl_ = nullptr;
  }
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept : impl_(other.impl_) { other.impl_ = nullptr; }

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    if (impl_ != nullptr) {
      if (!impl_->exited && impl_->process) {
        terminate();
      }
      delete impl_;
    }
    impl_ = other.impl_;
    other.impl_ = nullptr;
  }
  return *this;
}

std::optional<ChildProcess> ChildProcess::launch(const std::string& exe,
                                                 const std::vector<std::string>& args,
                                                 const std::string& capture_dir,
                                                 std::string& error) {
  std::error_code filesystem_error;
  std::filesystem::create_directories(std::filesystem::path(capture_dir), filesystem_error);
  static std::atomic<unsigned long long> sequence{0};
  const unsigned long long ordinal = ++sequence;
  const std::string capture =
      (std::filesystem::path(capture_dir) /
       ("capture-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(ordinal) + ".txt"))
          .string();

  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  attributes.lpSecurityDescriptor = nullptr;
  Handle capture_file(CreateFileW(widen(capture).c_str(), GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!capture_file) {
    error = "cannot create the capture file";
    return std::nullopt;
  }

  std::wstring command_line = quote_argument(widen(exe));
  for (const std::string& arg : args) {
    command_line.push_back(L' ');
    command_line.append(quote_argument(widen(arg)));
  }

  Handle stdin_read;
  Handle stdin_write;
  {
    HANDLE read_end = nullptr;
    HANDLE write_end = nullptr;
    if (CreatePipe(&read_end, &write_end, &attributes, 0) == FALSE) {
      error = "cannot create the child's input pipe";
      return std::nullopt;
    }
    stdin_read.reset(read_end);
    stdin_write.reset(write_end);
    if (SetHandleInformation(write_end, HANDLE_FLAG_INHERIT, 0) == FALSE) {
      error = "cannot configure the child's input pipe";
      return std::nullopt;
    }
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = capture_file.get();
  startup.hStdError = capture_file.get();
  startup.hStdInput = stdin_read.get();

  PROCESS_INFORMATION process_info{};
  const std::wstring working_directory = widen(capture_dir);
  const BOOL created = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, TRUE,
                                      CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr,
                                      working_directory.c_str(), &startup, &process_info);
  if (created == FALSE) {
    error = "CreateProcess failed with error " + std::to_string(GetLastError());
    return std::nullopt;
  }
  Handle process(process_info.hProcess);
  Handle thread(process_info.hThread);
  stdin_read.reset();

  Handle job(CreateJobObjectW(nullptr, nullptr));
  if (job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits,
                                sizeof(limits)) != FALSE) {
      if (AssignProcessToJobObject(job.get(), process.get()) == FALSE) {
        error = "cannot assign the child process to its job object";
        static_cast<void>(TerminateProcess(process.get(), 1));
        return std::nullopt;
      }
    }
  }
  if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
    error = "cannot resume the child process";
    static_cast<void>(TerminateProcess(process.get(), 1));
    return std::nullopt;
  }

  ChildProcess child;
  child.impl_ = new Impl();
  child.impl_->process = std::move(process);
  child.impl_->job = std::move(job);
  child.impl_->stdin_write = std::move(stdin_write);
  child.impl_->capture_path = capture;
  child.impl_->pid = process_info.dwProcessId;
  return std::optional<ChildProcess>(std::move(child));
}

bool ChildProcess::running() {
  if (impl_ == nullptr || !impl_->process) {
    return false;
  }
  if (impl_->exited) {
    return false;
  }
  if (wait_for(impl_->process.get(), 0) == WAIT_OBJECT_0) {
    static_cast<void>(GetExitCodeProcess(impl_->process.get(), &impl_->exit_code));
    impl_->exited = true;
    return false;
  }
  return true;
}

bool ChildProcess::wait_for_exit(unsigned milliseconds) {
  if (impl_ == nullptr || !impl_->process) {
    return true;
  }
  if (impl_->exited) {
    return true;
  }
  if (wait_for(impl_->process.get(), milliseconds) != WAIT_OBJECT_0) {
    return false;
  }
  static_cast<void>(GetExitCodeProcess(impl_->process.get(), &impl_->exit_code));
  impl_->exited = true;
  return true;
}

bool ChildProcess::wait_for_exit_code(unsigned milliseconds, unsigned long& code) {
  if (!wait_for_exit(milliseconds)) {
    return false;
  }
  code = impl_->exit_code;
  return true;
}

void ChildProcess::terminate() {
  if (impl_ == nullptr || !impl_->process) {
    return;
  }
  if (!impl_->exited) {
    static_cast<void>(TerminateProcess(impl_->process.get(), 1));
    static_cast<void>(wait_for(impl_->process.get(), 10000));
    static_cast<void>(GetExitCodeProcess(impl_->process.get(), &impl_->exit_code));
    impl_->exited = true;
  }
}

unsigned long ChildProcess::exit_code() const { return impl_ == nullptr ? 0UL : impl_->exit_code; }

std::uint32_t ChildProcess::process_id() const { return impl_ == nullptr ? 0U : impl_->pid; }

std::string ChildProcess::captured_output() {
  if (impl_ == nullptr) {
    return std::string{};
  }
  std::ifstream file(impl_->capture_path, std::ios::binary);
  if (!file) {
    return std::string{};
  }
  std::ostringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

bool ChildProcess::wait_for_output(const std::string& needle, unsigned milliseconds) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
  while (true) {
    if (captured_output().find(needle) != std::string::npos) {
      return true;
    }
    if (!running()) {
      // The child exited; one final read decides the outcome.
      return captured_output().find(needle) != std::string::npos;
    }
    if (std::chrono::steady_clock::now() > deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

bool ChildProcess::write_stdin(const std::string& text) {
  if (impl_ == nullptr || !impl_->stdin_write) {
    return false;
  }
  DWORD written = 0;
  if (WriteFile(impl_->stdin_write.get(), text.data(), static_cast<DWORD>(text.size()), &written,
                nullptr) == FALSE) {
    return false;
  }
  static_cast<void>(FlushFileBuffers(impl_->stdin_write.get()));
  return written == text.size();
}

std::string make_temp_dir(const std::string& label, const std::string& root) {
  std::error_code error;
  const std::filesystem::path base = root.empty() ? std::filesystem::current_path(error)
                                                  : std::filesystem::path(root);
  const std::string name =
      label + "-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
  const std::filesystem::path directory = base / name;
  std::filesystem::create_directories(directory, error);
  if (error) {
    return std::string{};
  }
  return directory.string();
}

void remove_dir(const std::string& path) {
  std::error_code error;
  static_cast<void>(std::filesystem::remove_all(std::filesystem::path(path), error));
}

bool file_exists(const std::string& path) {
  std::error_code error;
  return std::filesystem::exists(std::filesystem::path(path), error);
}

bool wait_until(unsigned milliseconds, const std::function<bool()>& predicate) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
  while (true) {
    if (predicate()) {
      return true;
    }
    if (std::chrono::steady_clock::now() > deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

std::string scratch_dir() {
#ifdef RP_TEST_SCRATCH_DIR
  return std::string(RP_TEST_SCRATCH_DIR);
#else
  return std::string(".");
#endif
}

std::string coordinator_exe() {
#ifdef RP_COORDINATOR_EXE
  return std::string(RP_COORDINATOR_EXE);
#else
  return std::string{};
#endif
}

std::string publisher_exe() {
#ifdef RP_PUBLISHER_EXE
  return std::string(RP_PUBLISHER_EXE);
#else
  return std::string{};
#endif
}

}  // namespace rp_test
