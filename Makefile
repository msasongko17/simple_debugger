my_debugger: linenoise.cpp my_debugger.cpp linenoise.h
	g++ -Wall -W -Os -g -o my_debugger linenoise.cpp my_debugger.cpp

clean:
	rm -f my_debugger
