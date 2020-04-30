# ExportFucker
EAT Hook Lib Header-only

```cpp
	/**
	* @description Set the target module that has the function that you want hook.
	* @param {string?} The module name that's the target, if the string isn't set then the target module will be the own module
	* @returns {bool} return true if it worked
	*/
	bool set_target_module( std::string module_name = "");
	/**
	* @description Hook the Export Address of target function
	* @param {int} The hook function address
	* @param {string} The target function name
	* @returns {bool} return true if it worked
	*/
	bool hook( uintptr_t hook_addr, std::string function_name );
	/**
	* @description Search for a code cave on .text section
	* @returns {uintptr_t} return the code cave for our shellcode insertion
	*/
	uintptr_t find_code_cave( );
	/**
	* @description Returns the original address of hooked function
	* @param {string} Original function name
	* @returns {uintptr_t} original address
	*/
	uintptr_t get_hooked_func_real_address ( std::string function_name );
```
