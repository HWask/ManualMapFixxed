#include "MMap.h"

int main()
{
	auto pid = Utils::FindProcessByName("csgo.exe");
	Process proc;
	if (!proc.Attach(pid))
		TRACE("Could not attach to process");

	if (!proc.FindModules())
		TRACE("Could not find modules");

	MMap mmap(proc);
	mmap.CreateRPCEnvironment();
	mmap.MapModule(Utils::LookupDependancy("4hjgiosj.tmp"));

	return 0;
}