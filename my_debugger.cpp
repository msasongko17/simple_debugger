#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <vector>
#include <sstream>
#include "linenoise.h"

class debugger {
public:
	debugger (std::string prog_name, pid_t pid)
		: m_prog_name{std::move(prog_name)}, m_pid{pid} {}

	void run();

private:
	std::string m_prog_name;
	pid_t m_pid;
	void continue_execution();
	void handle_command(const std::string& line);
};

void debugger::run() {
	int wait_status;
	auto options = 0;
	std::cerr << "before waitpid\n";
	waitpid(m_pid, &wait_status, options);
	std::cerr << "after waitpid\n";

	char* line = nullptr;
	while((line = linenoise("minidbg> ")) != nullptr) {
		handle_command(line);
		linenoiseHistoryAdd(line);
		linenoiseFree(line);
	}
}

void debugger::continue_execution() {
        ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

        int wait_status;
        auto options = 0;
	std::cerr << "before waitpid\n";
        waitpid(m_pid, &wait_status, options);
	std::cerr << "after waitpid\n";
}

std::vector<std::string> split(const std::string &s, char delimiter) {
        std::vector<std::string> out{};
        std::stringstream ss {s};
        std::string item;

        while (std::getline(ss, item, delimiter)) {
                out.push_back(item);
        }

        return out;
}

bool is_prefix(const std::string& s, const std::string& of) {
        if (s.size() > of.size()) return false;
        return std::equal(s.begin(), s.end(), of.begin());
}

void debugger::handle_command(const std::string& line) {
	auto args = split(line, ' ');
	auto command = args[0];

	if(is_prefix(command, "continue")) {
		continue_execution();
	}
	else {
		std::cerr << "Unknown command\n";
	}
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cerr << "Program name not specified";
		return -1;
	}

	auto prog = argv[1];

	auto pid = fork();
	if(pid == 0) {
		// we're in the child process
		std::cerr << "before ptrace_traceme\n";
		ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
		std::cerr << "after ptrace_traceme\n";
		execl(prog, prog, nullptr);
	}
	else if (pid >= 1) {
		// we're in the parent process
		std::cout << "Started debugging process " << pid << '\n';
		debugger dbg(prog, pid);
		dbg.run();
	}
	return 0;
}
