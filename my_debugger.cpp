#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <sys/personality.h>
#include <sys/user.h>
#include <algorithm>
#include <iomanip>
#include "linenoise.h"

enum class reg {
	rax, rbx, rcx, rdx,
	rdi, rsi, rbp, rsp,
	r8, r9, r10, r11,
	r12, r13, r14, r15,
	rip, rflags, cs,
	orig_rax, fs_base,
	gs_base,
	fs, gs, ss, ds, es
};

constexpr std::size_t n_registers = 27;

struct reg_descriptor {
	reg r;
	int dwarf_r;
	std::string name;
};

const std::array<reg_descriptor, n_registers> g_register_descriptors {{
	{ reg::r15, 15, "r15"},
	{ reg::r14, 14, "r14"},
	{ reg::r13, 13, "r13"},
	{ reg::r12, 12, "r12"},
	{ reg::rbp, 6, "rbp" },
	{ reg::rbx, 3, "rbx" },
	{ reg::r11, 11, "r11" },
	{ reg::r10, 10, "r10" },
	{ reg::r9, 9, "r9" },
	{ reg::r8, 8, "r8" },
	{ reg::rax, 0, "rax" },
	{ reg::rcx, 2, "rcx" },
	{ reg::rdx, 1, "rdx" },
	{ reg::rsi, 4, "rsi" },
	{ reg::rdi, 5, "rdi" },
	{ reg::orig_rax, -1, "orig_rax" },
	{ reg::rip, -1, "rip" },
	{ reg::cs, 51, "cs" },
	{ reg::rflags, 49, "eflags" },
	{ reg::rsp, 7, "rsp" },
	{ reg::ss, 52, "ss" },
	{ reg::fs_base, 58, "fs_base" },
	{ reg::gs_base, 59, "gs_base" },
	{ reg::ds, 53, "ds" },
	{ reg::es, 50, "es" },
	{ reg::fs, 54, "fs" },
	{ reg::gs, 55, "gs" },
}};

uint64_t get_register_value(pid_t pid, reg r) {
	user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto&& rd) {return rd.r == r; });

	return *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors)));
}

void set_register_value(pid_t pid, reg r, uint64_t value) {
	user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto&& rd) {return rd.r == r;});

	*(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors))) = value;
	ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

uint64_t get_register_value_from_dwarf_register (pid_t pid, unsigned regnum) {
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [regnum](auto&& rd) {return rd.dwarf_r == regnum; });
	if (it == end(g_register_descriptors)) {
		throw std::out_of_range("Unknown dwarf register");
	}

	return get_register_value(pid, it->r);
}

std::string get_register_name(reg r) {
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto&& rd) { return rd.r == r; });
	return it->name;
}

reg get_register_from_name(const std::string& name) {
	auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [name](auto&& rd) { return rd.name == name; });
	return it->r;
}

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
	void dump_registers();
	uint64_t read_memory(uint64_t address);
	void write_memory(uint64_t address, uint64_t value);
};

void debugger::dump_registers() {
        for (const auto& rd : g_register_descriptors) {
                std::cout << rd.name << " 0x"
                        << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << std::endl;
        }
}

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

uint64_t debugger::read_memory(uint64_t address) {
	return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
	ptrace(PTRACE_POKEDATA, m_pid, address, value);
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
	else if (is_prefix(command, "register")) {
		if (is_prefix(args[1], "dump")) {
			dump_registers();
		}
		else if (is_prefix(args[1], "read")) {
			std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
		}
		else if (is_prefix(args[1], "write")) {
			std::string val {args[3], 2};
			set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
		}
	}
	else if(is_prefix(command, "memory")) {
		std::string addr {args[2], 2};

		if(is_prefix(args[1], "read")) {
			std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
		}
		if (is_prefix(args[1], "write")) {
			std::string val{ args[3], 2};
			write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
		}
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
