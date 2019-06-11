# ManualMapFixxed
This attempts to load a DLL in a stealthy way ommiting the need of using LoadLibrary. The whole PE File is mapped manually by
allocating then writing each section into memory. Offsets, Relocations and imports are handled properly which is enough to successfully
inject most DLLs. If a dependancy is missing it is manually mapped aswell.
