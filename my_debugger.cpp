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
#include <dwarf.h>
#include <libdwarf.h>
#include <fstream>
#include <string.h>
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
		: m_prog_name{std::move(prog_name)}, m_pid{pid} {
		Dwarf_Error error;
		dwarf_init_path(m_prog_name.c_str(), nullptr, 0,
				DW_GROUPNUMBER_ANY, 0, nullptr, 
				&dbg, &error);
		std::cerr << "constructor called\n";
	}
	~debugger () {
		dwarf_finish(dbg);
		std::cerr << "destructor called\n";
	}
	void run();
	void set_breakpoint_at_address(std::intptr_t addr);

private:
	Dwarf_Debug dbg;
	std::string m_prog_name;
	uint64_t m_load_address;
	pid_t m_pid;
	std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
	void continue_execution();
	void handle_command(const std::string& line);
	void dump_registers();
	uint64_t read_memory(uint64_t address);
	void write_memory(uint64_t address, uint64_t value);
	uint64_t get_pc();
	void set_pc(uint64_t pc);
	void step_over_breakpoint();
	void wait_for_signal();
	void initialize_load_address();
	uint64_t offset_load_address(uint64_t addr);
	void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context);
	siginfo_t get_signal_info();
        void handle_sigtrap(siginfo_t info);
	int get_line_entry(Dwarf_Die cu_die,Dwarf_Error *error, Dwarf_Line* line_die, uint64_t pc, Dwarf_Line_Context* line_context);
	void get_line_die_by_pc(Dwarf_Debug dbg, Dwarf_Line* line_die, uint64_t pc, Dwarf_Line_Context* line_context);	
};

uint64_t debugger::get_pc() {
	return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
	set_register_value(m_pid, reg::rip, pc);
}

void debugger::step_over_breakpoint() {
	if (m_breakpoints.count(get_pc())) {
		auto& bp = m_breakpoints[get_pc()];

		if (bp.is_enabled()) {			
			bp.disable();
			ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
			wait_for_signal();
			bp.enable();
		}
	}
}

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

void debugger::initialize_load_address() {
	std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");
	std::string line;
	while(getline(map, line)) {
		// trim m_prog_name until after the last /
		std::string s(line);
		std::string exec_name(m_prog_name);
        	if(s.erase(0, s.find_last_of("/")+1) == exec_name.erase(0, exec_name.find_last_of("/")+1)) {
			line.erase(line.find_first_of("-"), line.length() - line.find_first_of("-"));
			m_load_address = std::stol(line, 0, 16);
			break;
		}
	}
	//std::cerr << std::hex << m_load_address << "\n";
}

uint64_t debugger::offset_load_address(uint64_t addr) {
	return addr - m_load_address;
}

void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context) {
	std::ifstream file {file_name};

	auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
	auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line: 0) + 1;

	char c{};
	auto current_line = 1u;
	//Skip lines up until start line
	while (current_line != start_line && file.get(c)) {
		if(c == '\n') {
			++current_line;
		}
	}

	//Output cursor if we are at the current line
	std::cerr << (current_line==line ? "> " : " ");

	// write lines up until end line
	while (current_line <= end_line && file.get(c)) {
		std::cerr << c;
		if(c == '\n') {
			++current_line;
			std::cerr << (current_line==line ? "> ": " ");
		}
	}

	std::cerr << "\n";
}

siginfo_t debugger::get_signal_info() {
	siginfo_t info;
	ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
	return info;
}

void debugger::handle_sigtrap(siginfo_t info) {
//#if 0
	switch (info.si_code) {
		// these values will be set if a breakpoint is hit
		case SI_KERNEL:
		case TRAP_BRKPT:
			{
				set_pc(get_pc()-1);
				std::cerr << "Hit breakpoint at address 0x" << std::hex << get_pc() << "\n";
				auto offset_pc = offset_load_address(get_pc());
				//auto line_entry = get_line_entry_from_pc(offset_pc);
				Dwarf_Line_Context line_context = 0;
  				Dwarf_Line line_die = nullptr;
				get_line_die_by_pc(dbg, &line_die, offset_pc, &line_context);
				if(line_die != nullptr) {
	  				long long unsigned int lineno;
	  				char *filename;
					Dwarf_Error error;
	  				//Dwarf_Addr line_addr;
	  				dwarf_lineno(line_die, &lineno, &error);
	  				dwarf_linesrc(line_die, &filename, &error);
					print_source(filename, lineno, 5);
	  				//dwarf_lineaddr(line_die, &line_addr, &error);
	  				//std::cerr << "file " << filename << ", line no " << std::dec << lineno << ", address " << std::hex << line_addr << "\n";
  				}
				//print_source(line->file->path, line_entry->line);
				return;
			}
		case TRAP_TRACE:
			return;
		default:
			std::cerr << "Unknown SIGTRAP code " << info.si_code << std::endl;
			return;
	}
//#endif
}

int debugger::get_line_entry(Dwarf_Die cu_die,Dwarf_Error *error, Dwarf_Line* line_die, uint64_t pc, Dwarf_Line_Context* line_context)
{
    /* EXAMPLE: DWARF2-DWARF5  access.  */
    Dwarf_Line  *linebuf = 0;
    Dwarf_Signed linecount = 0;
    Dwarf_Line  *linebuf_actuals = 0;
    Dwarf_Signed linecount_actuals = 0;
    //Dwarf_Line_Context line_context = 0;
    Dwarf_Small  table_count = 0;
    Dwarf_Unsigned lineversion = 0;
    int sres = 0;
    /* ... */
    /*  we use 'return' here to signify we can do nothing more
        at this point in the code. */
    sres = dwarf_srclines_b(cu_die,&lineversion,
        &table_count,line_context,error);
    if (sres != DW_DLV_OK) {
        /*  Handle the DW_DLV_NO_ENTRY  or DW_DLV_ERROR
            No memory was allocated so there nothing
            to dealloc. */
        return sres;
    }
    if (table_count == 0) {
        /*  A line table with no actual lines.  */
        /*...do something, see dwarf_srclines_files_count()
            etc below. */

        dwarf_srclines_dealloc_b(*line_context);
        /*  All the memory is released, the line_context
            and linebuf zeroed now
            as a reminder they are stale. */
        linebuf = 0;
        *line_context = 0;
    } else if (table_count == 1) {
    Dwarf_Signed i = 0;
        Dwarf_Signed baseindex = 0;
        Dwarf_Signed file_count = 0;
        Dwarf_Signed endindex = 0;
        /*  Standard dwarf 2,3,4, or 5 line table */
        /*  Do something. */

        /*  First let us index through all the files listed
            in the line table header. */
        sres = dwarf_srclines_files_indexes(*line_context,
            &baseindex,&file_count,&endindex,error);
        if (sres != DW_DLV_OK) {
            /* Something badly wrong! */
            return sres;
        }
        /*  Works for DWARF2,3,4 (one-based index)
            and DWARF5 (zero-based index) */
        for (i = baseindex; i < endindex; i++) {
            Dwarf_Unsigned dirindex = 0;
            Dwarf_Unsigned modtime = 0;
            Dwarf_Unsigned flength = 0;
            Dwarf_Form_Data16 *md5data = 0;
            int vres = 0;
            const char *name = 0;

            vres = dwarf_srclines_files_data_b(*line_context,i,
                &name,&dirindex, &modtime,&flength,
                &md5data,error);
	    //std::cerr << "file " << name << "\n";
            if (vres != DW_DLV_OK) {
                /* something very wrong. */
                return vres;
            }
            /* do something */
        }

        /*  For this case where we have a line table we will likely
            wish to get the line details: */
        sres = dwarf_srclines_from_linecontext(*line_context,
            &linebuf,&linecount,
            error);
        if (sres != DW_DLV_OK) {
            /* Error. Clean up the context information. */
            dwarf_srclines_dealloc_b(*line_context);
            return sres;
        }
        /* The lines are normal line table lines. */
	int index = -1;
        for (i = 0; i < linecount; ++i) {
            /* use linebuf[i] */
	    //std::cerr << "address " << linebuf[i]->li_address << ", line " << linebuf[i]->li_line << "\n";
	    //long long unsigned int lineno;
	    Dwarf_Error error;
#if 0
	    dwarf_lineno(linebuf[i], &lineno, &error);
	    char *filename;
	    Dwarf_Addr line_addr;
	    dwarf_linesrc(linebuf[i], &filename, &error);
#endif
	    Dwarf_Addr line_addr;
	    dwarf_lineaddr(linebuf[i], &line_addr, &error);
	    if(pc >= line_addr) {
		    index = i;
	    } else {
		    break;
	    }
	    //std::cerr << "file " << filename << ", line no " << std::dec << lineno << ", address " << std::hex << line_addr << "\n";
        }
	if(index != -1)
		*line_die = linebuf[index];
        //dwarf_srclines_dealloc_b(line_context);
        /*  All the memory is released, the line_context
            and linebuf zeroed now as a reminder they are stale */
        linebuf = 0;
        //line_context = 0;
        linecount = 0;
    } else {
        Dwarf_Signed i = 0;
        /*  ASSERT: table_count == 2,
            Experimental two-level line table. Version 0xf006
            We do not define the meaning of this non-standard
            set of tables here. */

        /*  For 'something C' (two-level line tables)
            one codes something like this
            Note that we do not define the meaning or
            use of two-level line
            tables as these are experimental, not standard DWARF. */
        sres = dwarf_srclines_two_level_from_linecontext(*line_context,
            &linebuf,&linecount,
            &linebuf_actuals,&linecount_actuals,
            error);
        if (sres == DW_DLV_OK) {
            for (i = 0; i < linecount; ++i) {
                /*  use linebuf[i], these are the 'logicals'
                    entries. */
            }
            for (i = 0; i < linecount_actuals; ++i) {
                /*  use linebuf_actuals[i], these are the
                    actuals entries */
            }
            dwarf_srclines_dealloc_b(*line_context);
            *line_context = 0;
            linebuf = 0;
            linecount = 0;
            linebuf_actuals = 0;
            linecount_actuals = 0;
        } else if (sres == DW_DLV_NO_ENTRY) {
            /* This should be impossible, but do something.   */
            /* Then Free the line_context */
            dwarf_srclines_dealloc_b(*line_context);
            *line_context = 0;
            linebuf = 0;
            linecount = 0;
            linebuf_actuals = 0;
            linecount_actuals = 0;
        } else {
            /*  ERROR, show the error or something.
                Free the line_context. */
            dwarf_srclines_dealloc_b(*line_context);
            *line_context = 0;
            linebuf = 0;
            linecount = 0;
            linebuf_actuals = 0;
            linecount_actuals = 0;
        }
    }
    return DW_DLV_OK;
}

void debugger::get_line_die_by_pc(Dwarf_Debug dbg, Dwarf_Line* line_die, uint64_t pc, Dwarf_Line_Context* line_context) {
    int i = 0;
    for (;;) {
        Dwarf_Unsigned cu_header_length = 0;
        Dwarf_Half version_stamp = 0;
        Dwarf_Unsigned abbrev_offset = 0;
        Dwarf_Half address_size = 0;
        Dwarf_Half length_size = 0;
        Dwarf_Half extension_size = 0;
        Dwarf_Sig8 type_signature;
        Dwarf_Unsigned typeoffset = 0;
        Dwarf_Unsigned next_cu_header_offset = 0;
        Dwarf_Half header_cu_type = 0;
        Dwarf_Error error;

        std::cout << "iteration " << i << "\n";
        int res = dwarf_next_cu_header_d(
            dbg,
            true, // is_info
            &cu_header_length,
            &version_stamp,
            &abbrev_offset,
            &address_size,
            &length_size,
            &extension_size,
            &type_signature,
            &typeoffset,
            &next_cu_header_offset,
            &header_cu_type,
            &error
        );

        // done
        if(res == DW_DLV_NO_ENTRY) {
            break;
        }

        Dwarf_Die sibling_die = nullptr;
        res = dwarf_siblingof_b(
            dbg,
            nullptr, // dw_die
            true,    // dw_is_info
            &sibling_die, // dw_return_siblingdie
            &error
        );

        if(res == DW_DLV_OK && sibling_die) {
            //iterate_dies_recursively(dbg, sibling_die);
	    get_line_entry(sibling_die,&error, line_die, pc, line_context);
            dwarf_dealloc(dbg, sibling_die, DW_DLA_DIE);
        }
        i++;
    }
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
	initialize_load_address();
	char* line = nullptr;
	while((line = linenoise("minidbg> ")) != nullptr) {
		handle_command(line);
		linenoiseHistoryAdd(line);
		linenoiseFree(line);
	}
}

#if 0
void debugger::continue_execution() {
        ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

        int wait_status;
        auto options = 0;
	std::cerr << "before waitpid\n";
        waitpid(m_pid, &wait_status, options);
	std::cerr << "after waitpid\n";
}
#endif

uint64_t debugger::read_memory(uint64_t address) {
	return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
	ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

void debugger::wait_for_signal() {
	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options);

	auto siginfo = get_signal_info();

	switch (siginfo.si_signo) {
//#if 0
		case SIGTRAP:
			handle_sigtrap(siginfo);
			break;
//#endif
		case SIGSEGV:
			std::cerr << "Segmentation fault is detected. Reason: " << siginfo.si_code << std::endl;
			break;
		//case SIGTRAP:
		default:
			std::cerr << "Received signal " << strsignal(siginfo.si_signo) << std::endl;
			//handle_sigtrap(siginfo);
	}
}

void debugger::continue_execution() {
	step_over_breakpoint();
	ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
	wait_for_signal();
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
