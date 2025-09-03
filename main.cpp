#include "debugger.hpp"


int main(size_t argc, char** argv, char** envp)
{
	Debugger debug = Debugger();
	debug.run(argv[1]);
	return 0;
}