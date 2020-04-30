#include "ExportFucker.h"
#pragma once

namespace export_fucker
{
	PIMAGE_DOS_HEADER				 dos_header;
	PIMAGE_NT_HEADERS				 nt_headers;
	PIMAGE_OPTIONAL_HEADER			 op_header;
	PIMAGE_DATA_DIRECTORY			 data_dir;
	PIMAGE_EXPORT_DIRECTORY			 export_dir;
	PIMAGE_SECTION_HEADER            sec_header;
	std::string						 module_target;
	size_t							 module_size;

	// Stores real addresses of hooked functions
	std::map<std::string, uintptr_t> hooked_funcs;
}

bool export_fucker::set_target_module( std::string module_name )
{
	// Checks if module name is empty if it's we'll set our own module as the target
	if ( !module_name.empty( ) )
	{
		// Check if module exists
		if ( !GetModuleHandleA( module_name.c_str( ) ) )
			return false;

		// Gets DOS Header
		export_fucker::dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( GetModuleHandleA( module_name.c_str( ) ) );
	}
	else export_fucker::dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( GetModuleHandleA( nullptr ) ); // Gets DOS Header of our own 


	// Gets NT Header
	export_fucker::nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS >( ( char* ) export_fucker::dos_header + export_fucker::dos_header->e_lfanew );

	// Gets Optional Header
	export_fucker::op_header = &export_fucker::nt_headers->OptionalHeader;


	// Gets Data Directory
	export_fucker::data_dir = export_fucker::op_header->DataDirectory;

	// Gets Export Directory Table
	export_fucker::export_dir = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( ( char* ) export_fucker::dos_header + export_fucker::data_dir [ 0 ].VirtualAddress );

	//Gets first section header
	export_fucker::sec_header = IMAGE_FIRST_SECTION( export_fucker::nt_headers );

	// .text string on section name
	char text_sec_string [ 8 ] = { '.', 't', 'e', 'x', 't', '\x00', '\x00', '\x00' };

	// Find the .text section header
	for ( size_t i = 0; i < export_fucker::nt_headers->FileHeader.NumberOfSections; ++i )
	{
		// The section name is UTF-8 Null padded string with 8 characters, i'm comparing if the section name is .text
		if ( memcmp( &export_fucker::sec_header->Name, text_sec_string, 8 ) == 0 )
			break;

		// Walks on the section headers
		++export_fucker::sec_header;
	}

	// Gets module total size
	export_fucker::module_size = export_fucker::sec_header->SizeOfRawData;
}

bool export_fucker::hook( uintptr_t hook_addr, std::string function_name )
{
	// Gets Name Pointer Table
	const auto               name_rva = *reinterpret_cast< uintptr_t* >( ( char* ) export_fucker::dos_header + export_fucker::export_dir->AddressOfNames );
	// Gets Name Pointer Table Length
	const auto			     name_length = export_fucker::export_dir->NumberOfNames;
	// The index will be the value that we can use on Export Address Table
	int					     index = { 0 };
	// Gets Export Address Table
	auto					 export_address_table = reinterpret_cast< uintptr_t* >( ( char* ) export_fucker::dos_header + export_fucker::export_dir->AddressOfFunctions );


	for ( int size = 0; ; ++size )
	{
		// Reads function name
		std::string buffer( reinterpret_cast< char* >( ( char* ) export_fucker::dos_header + name_rva + size ) );

		// Next string will be the last one size + size
		size += buffer.size( );

		// Compares if buffer matches with target function name
		if ( buffer == function_name )
			break;

		// If the functiom name wasn't found
		if ( buffer.length( ) < name_length )
			return false;

		//Increases the index that will be very important
		++index;
	}

	// Gets RVA Address of Target Function
	uintptr_t addr_real_func = export_address_table [ index ];

	// Sums the RVA with the module base
	addr_real_func = reinterpret_cast< uintptr_t >( ( char* ) export_fucker::dos_header + addr_real_func );

	// Stores real address on map
	export_fucker::hooked_funcs.insert( std::pair<std::string, uintptr_t>( function_name, addr_real_func ) );

	// Call find_code_cave for find a place for our shellcode
	uintptr_t code_cave_addr = export_fucker::find_code_cave( );


	// If there's no place return false
	if ( !code_cave_addr )
		return false;

	// Shellcode: jmp address
	char shellcode [ ] = { '\xEA', '\x00', '\x00', '\x00', '\x00'};

	// Place the address on shellcode
	memcpy( shellcode + 1, &hook_addr, sizeof( int32_t ) );

	// Stores the old protection
	DWORD old_protect = { 0 };

	// Change the protection to READ WRITE EXECUTE because I'll write the shellcode on .text
	if ( !VirtualProtect( reinterpret_cast< char* >( export_fucker::dos_header ), export_fucker::module_size, PAGE_EXECUTE_READWRITE, &old_protect ) )
		return false;

	// Copy the shellcode to code_cave
	memcpy( reinterpret_cast< void* >( code_cave_addr ), shellcode, 5 );

	// Change the protection to EXECUTE because I'll let the .text as it was before.
	if ( !VirtualProtect( reinterpret_cast< char* >( export_fucker::dos_header ), export_fucker::module_size, old_protect, &old_protect ) )
		return false;


	// Calculate code cade rva
	uintptr_t code_cave_rva = code_cave_addr - reinterpret_cast< uintptr_t >( export_fucker::dos_header );

	if ( !VirtualProtect( reinterpret_cast< void* >( export_address_table ), sizeof( int32_t ), PAGE_READWRITE, &old_protect ) )
		return false;

	// Write RVA to Export Address Table, EAT index hooked baby
	export_address_table [ index ] = code_cave_rva;

	// Set the address range protection for what it's before.
	if ( !VirtualProtect( reinterpret_cast< void* >( export_address_table ), sizeof( int32_t ), old_protect, &old_protect ) )
		return false;

	// return true because the hook was a success
	return true;
}


uintptr_t export_fucker::find_code_cave( )
{
	// Stores the old protection
	DWORD old_protect = { 0 };

	// Set the .text section protection for read, write and execute because i'll need to READ the opcodes and search for 5 null-bytes
	if ( !VirtualProtect( reinterpret_cast< char* >( export_fucker::dos_header ), export_fucker::module_size, PAGE_EXECUTE_READWRITE, &old_protect ) )
		return false;


	// Find a code cave for place shellcode
	for ( size_t i = export_fucker::module_size + reinterpret_cast< int32_t >( export_fucker::dos_header ); i > 0; i -= 5 )
	{
		// Intializes the mem buffer
		char mem_bytes [ 5 ] = { 0 };

		// Shellcode with 5 null-bytes XD idk why i did this
		char shellcode [ 5 ] = { '\x00', '\x00', '\x00', '\x00', '\x00' };

		// Copy the memory area to the mem buffer
		memcpy( &mem_bytes, reinterpret_cast< char* >( i ), 5 );

		// Compares if it has the space for placing the JMP shellcode, if has space, return the memory address
		if ( memcmp( &mem_bytes, &shellcode, 5 ) == 0 )
		{
			// Set the .text section protection for what it's before.
			if ( !VirtualProtect( reinterpret_cast< int32_t* >( export_fucker::dos_header ), export_fucker::module_size, PAGE_EXECUTE, &old_protect ) )
				return false;

			// returns code cave address
			return i;
		}
	}
}

uintptr_t export_fucker::get_hooked_func_real_address( std::string function_name )
{
	// Checks if function name is empty
	if ( !function_name.empty( ) )
	{
		// Get hooked function real address using the map
		const auto real_addr = export_fucker::hooked_funcs.find( function_name )->second;
		return real_addr;
	}

	return 0;
}