#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <sys/personality.h>
#include "linenoise.h"

class breakpoint {
public:
        breakpoint(pid_t pid, std::intptr_t addr)
                : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{}
        {}

	breakpoint()
                : m_pid{0}, m_addr{0}, m_enabled{false}, m_saved_data{}
        {}
        void enable();
        void disable();

        auto is_enabled() const -> bool { return m_enabled; }
        auto get_address() const -> std::intptr_t { return m_addr; }
private:
        pid_t m_pid;
        std::intptr_t m_addr;
        bool m_enabled;
        uint8_t m_saved_data; //data which used to be at the breakpoint address
};

class debugger {
public:
	debugger (std::string prog_name, pid_t pid)
		: m_prog_name{std::move(prog_name)}, m_pid{pid} {}

	void run();
	void set_breakpoint_at_address(std::intptr_t addr);

private:
	std::string m_prog_name;
	pid_t m_pid;
	std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
	void continue_execution();
	void handle_command(const std::string& line);
};

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
	std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
	breakpoint bp {m_pid, addr};
	bp.enable();
	m_breakpoints[addr] = bp;
}

void breakpoint::enable() {
	auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
	m_saved_data = static_cast<uint8_t>(data & 0xff); //save bottom byte
	uint64_t int3 = 0xcc;
	uint64_t data_with_int3 = ((data & ~0xff) | int3); // set bottom byte to 0xcc
	ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

	m_enabled = true;
}

void breakpoint::disable() {
	auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
	auto restored_data = ((data & ~0xff) | m_saved_data);
	ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

	m_enabled = false;
}

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
	else if(is_prefix(command, "break")) {
		std::string addr {args[1], 2}; //naively assume that the user has written 0xADDRESS
		set_breakpoint_at_address(std::stol(addr, 0, 16));
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
		//personality(ADDR_NO_RANDOMIZE);
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
