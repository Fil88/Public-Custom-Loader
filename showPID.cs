//C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:showPid.exe showPid.cs
//showPid.exe when executed will display the PID process ID
//Now use donut to generate shellcode for that PE 
//the paylod building logic is here: https://github.com/dtrizna/dotNETinject/blob/master/generate_sc.py
// Install it (python -m pip install donut-shellcode) &&
// python generate_cs.py showPid.exe x64. Will create 2 file, one with the actual shellcode in bin format, the other one a base64 versione of the Bin 

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;

namespace donutTestSimpleDotNetApp
{
    class Program
    {
        static void Main(string[] args)
        {
            int nProcessID = Process.GetCurrentProcess().Id;
            string message = nProcessID.ToString();
            MessageBox.Show(message,"Box from PID:");
        }
    }
}