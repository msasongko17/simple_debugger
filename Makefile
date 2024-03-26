my_debugger: linenoise.cpp my_debugger.cpp linenoise.h
	g++ -Wall -W -Os -g -o my_debugger linenoise.cpp my_debugger.cpp ../libdwarf-install/lib/libdwarf.a -I../libdwarf-install/include/libdwarf-0 -lzstd -lz

clean:
	rm -f my_debugger
