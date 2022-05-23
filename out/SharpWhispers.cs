// Author: Dimitri (GlenX) Di Cristofaro (@d_glenx)
// SECFORCE LTD
// Read the blogpost: https://secforce.com/blog/sharpasm-sharpwhispers
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// needed for GetApiHash()
using System.Security.Cryptography;
using System.Text;

// Data types
using Data = SharpWhispers.Data;

// define DWORD to be a bit more C-friendly - and a bit lazy :)
using DWORD = System.Int32;

namespace SharpWhispers
{
    class SyscallSolver
    {

        // https://stackoverflow.com/questions/28478520/getting-error-for-isnullorwhitespace
        // .NET < 4.0 does not implement IsNullOrWhiteSpace
        private static bool IsNullOrWhiteSpace(String value)
        {
            if (value == null) return true;

            for (int i = 0; i < value.Length; i++)
            {
                if (!Char.IsWhiteSpace(value[i])) return false;
            }

            return true;
        }

        public static string key = "C752B1A4";

        public struct SW2_SYSCALL_ENTRY
        {
            public string Hash;
            public IntPtr Address;
        }

        public static List<SW2_SYSCALL_ENTRY> SyscallList = new List<SW2_SYSCALL_ENTRY>();


	public static string GetApiHash(string apiName, string key)
	{
		// https://gist.github.com/jasny/2200f68f8109b22e61863466374a5c1d
            byte[] keyByte = new ASCIIEncoding().GetBytes(key);
            byte[] messageBytes = new ASCIIEncoding().GetBytes(apiName);

            byte[] hashmessage = new HMACMD5(keyByte).ComputeHash(messageBytes);

            // to lowercase hexits
            String.Concat(Array.ConvertAll(hashmessage, x => x.ToString("x2")));
    

            string hash_str = BitConverter.ToString(hashmessage).Replace("-", "");
            return hash_str;
            // to base64
            //return Convert.ToBase64String(hashmessage);
	}

        // Wrapper function for GetApiHash
        public static string SW2_HashSyscall(string FunctionName)
        {
            return GetApiHash(FunctionName, key);
        }

        /// <summary>
        /// Given a module base address, retrieves all the syscalls and order them by address in ascending order to allow system call number extraction.
        /// Credits:
        /// freshycalls: https://www.crummie5.club/freshycalls/ (@ElephantSe4l)
        /// Syswhispers2: https://github.com/jthuraisamy/SysWhispers2 (@Jackson_T , @modexpblog)
        /// The function is a modified version of DInvoke.DynamicInvoke.Generic.GetExportAddress by Ruben Boonen (@FuzzySec)
        /// </summary>
        /// <author>Dimitri (GlenX) Di Cristofaro (@d_glenx)</author>
        /// <param name="moduleBase">A pointer to the NTDLL.DLL base address where the module is loaded in the current process.</param>
        /// <returns>bool if/when the syscall list is populated</returns>
        public static bool PopulateSyscallList(IntPtr moduleBase)
        {
            // Return early if the list is already populated.
            if (SyscallList.Count > 0) return true;

            var functionPtr = IntPtr.Zero;

            // Temp Entry to assign the attributes values before adding the element to the list
            SW2_SYSCALL_ENTRY Temp_Entry;

            try
            {
                // Traverse the PE header in memory
                var peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
                var optHeader = moduleBase.ToInt64() + peHeader + 0x18;
                var magic = Marshal.ReadInt16((IntPtr)optHeader);
                long pExport = 0;

                if (magic == 0x010b) pExport = optHeader + 0x60;
                else pExport = optHeader + 0x70;

                var exportRva = Marshal.ReadInt32((IntPtr)pExport);
                var ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x10));
                var numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x18));
                var functionsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x1C));
                var namesRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x20));
                var ordinalsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x24));


                for (var i = 0; i < numberOfNames; i++)
                {
                    var functionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRva + i * 4))));
                    // We duplicated the function in two namespaces to maintain compatibility with DInvoke lib
                    if (IsNullOrWhiteSpace(functionName)) continue;


                    // Check if is a syscall
                    if (functionName.StartsWith("Zw"))
                    {
                        var functionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                        var functionRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                        functionPtr = (IntPtr)((long)moduleBase + functionRva);

                        Temp_Entry.Hash = SW2_HashSyscall(functionName);
                        Temp_Entry.Address = functionPtr;
                        
                        // Add syscall to the list
                        SyscallList.Add(Temp_Entry);

                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse module exports.");
            }



            // Sort the list by address in ascending order.
            for (DWORD i = 0; i < SyscallList.Count - 1; i++)
            {
                for (DWORD j = 0; j < SyscallList.Count - i - 1; j++)
                {
                    if (SyscallList[j].Address.ToInt64() > SyscallList[j + 1].Address.ToInt64())
                    {
                        // Swap entries.
                        SW2_SYSCALL_ENTRY TempSwapEntry;

                        TempSwapEntry.Hash = SyscallList[j].Hash;
                        TempSwapEntry.Address = SyscallList[j].Address;


                        Temp_Entry.Hash = SyscallList[j + 1].Hash;
                        Temp_Entry.Address = SyscallList[j + 1].Address;
                                               
                        SyscallList[j] = Temp_Entry;
                        
                        
                        SyscallList[j + 1] = TempSwapEntry;

                    }
                }
            }

            Console.WriteLine("[i] Syscall List Created!\n");

            return true;
        }

        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. 
        /// The function uses SharpASM to call a tiny shellcode that will return the address of PEB
        /// by reading it in the appropriate register. This base address could be passed to 
        /// GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function parses the _PEB_LDR_DATA structure.
        /// The function is a modified version of DInvoke.DynamicInvoke.Generic.GetPebLdrModuleEntry by Ruben Boonen (@FuzzySec).
        /// </summary>
        /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        public static IntPtr GetPebLdrModuleEntry(string dllName)
        {
            // Get _PEB pointer
            //var pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));

            IntPtr ppeb = PEB.GetPEB();

            // Set function variables
            uint ldrDataOffset = 0;
            uint inLoadOrderModuleListOffset = 0;

            if (IntPtr.Size == 4)
            {
                ldrDataOffset = 0xc;
                inLoadOrderModuleListOffset = 0xC;
            }
            else
            {
                ldrDataOffset = 0x18;
                inLoadOrderModuleListOffset = 0x10;
            }

            // Get module InLoadOrderModuleList -> _LIST_ENTRY
            //var PEB_LDR_DATA = Marshal.ReadIntPtr((IntPtr)((ulong)pbi.PebBaseAddress + ldrDataOffset));
            var PEB_LDR_DATA = Marshal.ReadIntPtr((IntPtr)((ulong)ppeb + ldrDataOffset));


            var pInLoadOrderModuleList = (IntPtr)((ulong)PEB_LDR_DATA + inLoadOrderModuleListOffset);
            var le = (Data.Native.LIST_ENTRY)Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(Data.Native.LIST_ENTRY));

            // Loop entries
            var flink = le.Flink;
            var hModule = IntPtr.Zero;
            var dte = (Data.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Data.PE.LDR_DATA_TABLE_ENTRY));
            while (dte.InLoadOrderLinks.Flink != le.Blink)
            {
                // Match module name
                if (Marshal.PtrToStringUni(dte.FullDllName.Buffer).EndsWith(dllName, StringComparison.OrdinalIgnoreCase))
                {
                    hModule = dte.DllBase;
                }

                // Move Ptr
                flink = dte.InLoadOrderLinks.Flink;
                dte = (Data.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Data.PE.LDR_DATA_TABLE_ENTRY));
            }

            return hModule;
        }


        public static DWORD SW2_GetSyscallNumber(string FunctionHash)
        {
            // Uses .NET System.Diagnostics.Process class
            //var hModule = DynamicInvoke.Generic.GetLoadedModuleAddress("ntdll.dll");

            // Uses PEB
            var hModule = GetPebLdrModuleEntry("ntdll.dll");


            // Ensure SW2_SyscallList is populated.
            if (!PopulateSyscallList(hModule)) return -1;

            for (DWORD i = 0; i < SyscallList.Count; i++)
            {
                if (FunctionHash.Equals(SyscallList[i].Hash, StringComparison.OrdinalIgnoreCase)) return i;
            }

            return -1;
        }
    }
}
