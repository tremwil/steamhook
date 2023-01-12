# steamhook

steamhook provides APIs for hooking and calling internal Steam IPC endpoints directly from the name of the interface and function. It obtains these names and more required information (such as vtables, interface instances, IPC call IDs, etc) by performing static analysis of the 32-bit Windows `steamclient.dll` binary.

This project is still very young as as such severely lacks documentation and not all provided APIs may be convenient to use, but is fully functionnal. For usage examples, see the source code of the `test_dll` and `test_launcher` binary crates. 

### Roadmap (roughly in order of priority)
- Cleaning up the API and adding proper documentation
- Reversing the internal callback dispatching mechanisms and providing APIs for callback hooking/fabrication. 

### Not on the roadmap
- Linux support

### Finding call n#mes and reversing the arguments
Compiling with `cargo build --target i686-pc-windows --all` and unning the `test_launcher` executable will generate an `interface_dump` folder in the same directory, with CSV tables listing all endpoint vtable offsets, names, call IDs and RVAs in the steamclient binary. You can then use the RVAs to view the endpoints in a reverse engineering suite like Ghidra and inspect argument types. Consulting the public Steamworks SDK refrence may also be useful; it appears that most endpoints sharing the name of their public SDK binding take the same parameters. 
