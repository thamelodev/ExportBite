#include <iostream>
#include "ExportFucker.h"


extern "C" __declspec( dllexport ) void run( )
{
    printf( "Oi!" );
}


extern "C" __declspec( dllexport ) void run2( )
{
    printf( "Oi!" );
}

extern "C" __declspec( dllexport ) void run3( )
{
    printf( "Oi!" );
}


int main()
{
	// Your target module
    export_fucker::set_target_module( "ExportFucker.exe" );

    printf( "Run3 Address: 0x%p\n", ( DWORD ) GetProcAddress( nullptr, "run3" ) );
	
    export_fucker::hook( reinterpret_cast< uintptr_t >( &run ), "run3" );
	
    printf( "Run3 Address After: 0x%p\n", ( DWORD ) GetProcAddress( nullptr, "run3" ) );

    
    system( "pause" );
}
