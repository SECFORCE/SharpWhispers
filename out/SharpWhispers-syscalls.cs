// Author: Dimitri (GlenX) Di Cristofaro (@d_glenx)
// This project uses Conditional Compilation Symbols to handle 32/64 bit compilation.
// In case Conditional Compilation Symbols are not set, this variable should be manually defined for 64 bit
//#define WIN64
using System;

// Delegates
using System.Runtime.InteropServices;

// Data types
using Data = SharpWhispers.Data;

// SharpWhispers
using SharpWhispers;

// SharpASM
// we call SharpASM.FindRWX()
using SharpASM = SharpAssembly.SharpASM;

// Delegates definitions
using Delegate = Delegates.SyscallDelegates.Delegate;

namespace Syscalls
{
    static class DynamicSysInvoke
    {
        /* UTILS */

        // Some code edited from: https://github.com/jhalon/SharpCall/blob/master/Syscalls.cs
        // and https://github.com/TheWover/DInvoke/tree/main/DInvoke/DInvoke


        // Syscall Stub
#if WIN64
        static byte[] bSyscallStub =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00,   // mov eax, 0x18 (NtAllocateVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };
#else
        static byte[] bSyscallStub =
        {
            0x55,                                       // push ebp
            0x8B, 0xEC,                                 // mov ebp,esp 
            0xB9, 0xAB, 0x00, 0x00, 0x00,               // mov ecx,AB   ; number of parameters
                                                        // push_argument:
            0x49,                                       // dec ecx
            0xFF, 0x74, 0x8D, 0x08,                     // push dword ptr ss:[ebp+ecx*4+8] ; parameter
            0x75, 0xF9,                                 // jne <x86syscallasm.push_argument>
                                                        // ; push ret_address_epilog
            0xE8, 0x00, 0x00, 0x00, 0x00,               // call <x86syscallasm.get_eip> ; get eip with ret-pop 
            0x58,                                       // pop eax
            0x83, 0xC0, 0x15,                           // add eax,15   ; Push return address
            0x50,                                       // push eax  
            0xB8, 0xCD, 0x00, 0x00, 0x00,               // mov eax,CD ; Syscall number
                                                        // ; Get Address from TIB
            0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,   // call dword ptr fs:[C0] ; call KiFastSystemCall
            0x8D, 0x64, 0x24, 0x04,                     // lea esp,dword ptr ss:[esp+4]
                                                        // ret_address_epilog:
            0x8B, 0xE5,                                 // mov esp,ebp
            0x5D,                                       // pop ebp
            0xC3                                        // ret
        };
#endif


        // Helper to zero memory without calling the api
        public static void RtlZeroMemory(IntPtr destination, int length)
        {
            unsafe
            {
                byte* ptr = (byte*)destination;
                for (uint i = 0; i < (uint)length; i++)
                {
                    *(ptr + i) = 0x00;
                }
            }
        }




        // Return the address of the syscall stub to be called
        public static IntPtr GetSyscallStub()
        {
            byte[] syscall = bSyscallStub;
            IntPtr stub = IntPtr.Zero;
            IntPtr syscallStubLength = (IntPtr)syscall.Length;

            stub = SharpASM.FindRWX((uint)syscall.Length);

            Console.WriteLine("[>] Code cave found! The syscall stub will be written @ " + string.Format("{0:X}", stub.ToInt64()));



            // Copy Stub
            unsafe
            {
                byte* ptr = (byte*)stub;
                for (uint i = 0; i < (uint)syscall.Length; i++)
                {
                    *(ptr + i) = syscall[i];
                }
            }
            return stub;
        }


        static void PrintMemory(IntPtr ptr, int Len)
        {
            byte[] tmp = new byte[Len];


            unsafe
            {
                byte* p = (byte*)ptr;
                for (uint i = 0; i < (uint)Len; i++)
                {
                    tmp[i] = *(p + i);
                }
            }

            Console.WriteLine("\n[i] Printing {0} bytes starting from 0x" + string.Format("{0:X}", SharpASM.PtrToInt(ptr)), Len );

            for(int i=0; i<Len; i++)
            {
                Console.Write("0x{0} ", tmp[i]);

            }
            Console.WriteLine();

        }


        /* Cleanup */
        public static bool isStubWritten(IntPtr dst, byte[] src)
        {
            bool ret = true;

            unsafe
            {
                byte* b = (byte*)dst;
                int i = 0;
                while (i < src.Length && *(b + i) == src[i])
                {
                    i++;
                }
                // if we exit from the loop before reaching the end of the array
                // it means that the stubs are different
                if (i != src.Length) return false;
            }
            //Console.WriteLine("the stub is there!");
            return ret;
        }

        public static void cleanupStub(IntPtr cleanupPtr, int cleanupSize)
        {
            if (cleanupPtr == IntPtr.Zero) return;

            // Check if the stub is still there
            if (!isStubWritten(cleanupPtr, bSyscallStub)) return;

            Console.WriteLine("Cleaning up...");
            RtlZeroMemory(cleanupPtr, cleanupSize);           
        }



        /* DInvoke Helpers */

        public static object DynamicFunctionInvoke(IntPtr functionPointer, Type functionDelegateType, ref object[] parameters)
        {
            var funcDelegate = Marshal.GetDelegateForFunctionPointer(functionPointer, functionDelegateType);
            return funcDelegate.DynamicInvoke(parameters);
        }



        // after 1000 subsequents failed calls it will stop re-trying
        static private uint failed_calls = 0;
        static private uint MAX_FAILED_CALLS = 1000;

        // call the system call using the hash of the function name
        // EVERY system call returns NTSTATUS - Data.Native.NTSTATUS
        public static Data.Native.NTSTATUS DynamicSyscallInvoke(string fHash, Type functionDelegateType, ref object[] parameters)
        {
            if (failed_calls > MAX_FAILED_CALLS) return Data.Native.NTSTATUS.Cancelled;

            Data.Native.NTSTATUS ret = Data.Native.NTSTATUS.Success;

            int syscallNumber = SyscallSolver.SW2_GetSyscallNumber(fHash);

            int num_of_params = parameters.Length;


#if WIN64
// Set syscall number on the 5th byte
            bSyscallStub[4] = (byte)syscallNumber;
#else
            // Set syscall number on the 27th byte
            bSyscallStub[26] = (byte)syscallNumber;
#endif

            // Number of parameters for 32 bit stack allocation 
#if !WIN64
            bSyscallStub[4] = (byte)num_of_params;
#endif


            IntPtr pStub = GetSyscallStub();



            //
            // Sometimes we get an AccessViolation because the page content gets zero'd 
            // Usually the second tries works
            // 
            try
            {
                ret = (Data.Native.NTSTATUS) DynamicFunctionInvoke(pStub, functionDelegateType, ref parameters);

                // Cleanup
                Console.WriteLine("[i] Syscall executed! Cleaning the system call stub from memory...");

            }
            catch(Exception e)
            {
                Console.WriteLine("[i] Exception Caught!");
                Console.WriteLine("[>] Exception: {0}", e);
                PrintMemory(pStub, bSyscallStub.Length);


                Console.WriteLine("\n[i]Trying again...\n");
                failed_calls++;
                ret = (Data.Native.NTSTATUS)DynamicSyscallInvoke(fHash, functionDelegateType, ref parameters);
                // We return directly, without deleting the old stub
                // it's likely that we are here because an Access Violation
                // has been thrown 
                // it's safer to keep that memory as is
                //
                // HYPOTHESIS:
                // the CLR doesn't know that pStub is filled with our data
                // so it will probably just overwrite it if it needs that memory.
                return ret;
            }



            //RtlZeroMemory(pStub, bSyscallStub.Length);

            cleanupStub(pStub, bSyscallStub.Length);


            // If we arrive here, it means that everything went ok
            // We reset the failed calls counter
            failed_calls = 0;

            return ret;
        }
    }




    
    // The following functions are just a refactoring of the DInvoke.DynamicInvoke.Native wrappers.
    // All credits to the original authors :) 
    // Credits: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
    // License: BSD 3-Clause

    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    static class Syscalls
    {



        /* Functions */
        
        public static  Data.Native.NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, Data.Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
{
    object[] funcargs =
    {
    threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
    sizeOfStack, maximumStackSize, attributeList
};

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("F4CF73001316720B424D62784E7AAF7D",
        typeof(Delegate.NtCreateThreadEx), ref funcargs);

    threadHandle = (IntPtr)funcargs[0];
    return retValue;
}


public static  Data.Native.NTSTATUS NtCreateSection(ref IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
{
    object[] funcargs =
    {
    sectionHandle, desiredAccess, objectAttributes, maximumSize, sectionPageProtection, allocationAttributes, fileHandle
};

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("06EFCC0AB6153F06536F00087E28740B", typeof(Delegate.NtCreateSection), ref funcargs);

    if (retValue != Data.Native.NTSTATUS.Success)
        throw new InvalidOperationException("Unable to create section, " + retValue);

    sectionHandle = (IntPtr)funcargs[0];
    maximumSize = (ulong)funcargs[3];

    return retValue;
}


public static  Data.Native.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
{
    object[] funcargs =
    {
    hProc, baseAddr
};

    var result = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("D7AA8775317505A9DB487ABBE386535E", typeof(Delegate.NtUnmapViewOfSection), ref funcargs);

    return result;
}


public static  Data.Native.NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, uint allocationType, uint win32Protect)
{
    object[] funcargs =
    {
    sectionHandle, processHandle, baseAddress, zeroBits, commitSize, sectionOffset, viewSize, inheritDisposition, allocationType,
    win32Protect
};

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("AF9BE845B1F2675D9294868281138CF3", typeof(Delegate.NtMapViewOfSection), ref funcargs);

    if (retValue != Data.Native.NTSTATUS.Success && retValue != Data.Native.NTSTATUS.ImageNotAtBase)
        throw new InvalidOperationException("Unable to map view of section, " + retValue);

    baseAddress = (IntPtr)funcargs[2];
    viewSize = (ulong)funcargs[6];

    return retValue;
}



public static  Data.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, Data.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
{
    int processInformationLength;
    uint retLen = 0;

    switch (processInfoClass)
    {
        case Data.Native.PROCESSINFOCLASS.ProcessWow64Information:
            pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
            DynamicSysInvoke.RtlZeroMemory(pProcInfo, IntPtr.Size);
            processInformationLength = IntPtr.Size;
            break;

        case Data.Native.PROCESSINFOCLASS.ProcessBasicInformation:
            var pbi = new Data.Native.PROCESS_BASIC_INFORMATION();
            pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
            DynamicSysInvoke.RtlZeroMemory(pProcInfo, Marshal.SizeOf(pbi));
            Marshal.StructureToPtr(pbi, pProcInfo, true);
            processInformationLength = Marshal.SizeOf(pbi);
            break;

        default:
            throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
    }

    object[] funcargs =
    {
    hProcess, processInfoClass, pProcInfo, processInformationLength, retLen
};

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("401C454020BE0FEE34568C6D8FE0E48C", typeof(Delegate.NtQueryInformationProcess), ref funcargs);

    if (retValue != Data.Native.NTSTATUS.Success)
        throw new UnauthorizedAccessException("Access is denied.");

    pProcInfo = (IntPtr)funcargs[2];

    return retValue;
}


public static  IntPtr NtOpenProcess(UInt32 ProcessId, Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess)
{
    // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
    IntPtr ProcessHandle = IntPtr.Zero;
    Data.Native.OBJECT_ATTRIBUTES oa = new Data.Native.OBJECT_ATTRIBUTES();
    Data.Native.CLIENT_ID ci = new Data.Native.CLIENT_ID();
    ci.UniqueProcess = (IntPtr)ProcessId;

    // Craft an array for the arguments
    object[] funcargs =
    {
        ProcessHandle, DesiredAccess, oa, ci
    };

    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("411CD9DF086D21D416BC31CB7D452995", typeof(Delegate.NtOpenProcess), ref funcargs);
    if (retValue != Data.Native.NTSTATUS.Success && retValue == Data.Native.NTSTATUS.InvalidCid)
    {
        throw new InvalidOperationException("An invalid client ID was specified.");
    }
    if (retValue != Data.Native.NTSTATUS.Success)
    {
        throw new UnauthorizedAccessException("Access is denied.");
    }

    // Update the modified variables
    ProcessHandle = (IntPtr)funcargs[0];

    return ProcessHandle;
}



public static  Data.Native.NTSTATUS NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect)
{

    object[] funcargs =
    {
        processHandle, baseAddress, zeroBits, regionSize, allocationType, protect
    };

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("CE4DF39B12EBD9DC200947D1FE248096", typeof(Delegate.NtAllocateVirtualMemory), ref funcargs);

    // Set out values
    baseAddress = (IntPtr)funcargs[1];
    regionSize = (IntPtr)funcargs[3];

    return retValue;
}


public static  void NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
{
    object[] funcargs =
    {
    processHandle, baseAddress, regionSize, freeType
};

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("3261D2EA1054D5B3C60C7FCC19F525B1", typeof(Delegate.NtFreeVirtualMemory), ref funcargs);

    switch (retValue)
    {
        case Data.Native.NTSTATUS.AccessDenied:
            throw new UnauthorizedAccessException("Access is denied.");
        case Data.Native.NTSTATUS.InvalidHandle:
            throw new InvalidOperationException("An invalid HANDLE was specified.");
    }

    if (retValue != Data.Native.NTSTATUS.Success)
        throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
}


public static  Data.Native.NTSTATUS NtQueryVirtualMemory(
    IntPtr processHandle,
    IntPtr baseAddress,
    Data.Native.MEMORYINFOCLASS memoryInformationClass,
    IntPtr memoryInformation,
    uint memoryInformationLength,
    ref uint returnLength)
{
    // TODO: NOT TESTED
    // Check that memoryInformation is handled correctly

    
    // Craft an array for the arguments
    object[] funcargs =
    {
        processHandle, baseAddress, memoryInformationClass, memoryInformation, memoryInformationLength, returnLength
    };

    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("C7FFB269469757559516DDACE6FEA4A2", typeof(Delegate.NtQueryVirtualMemory), ref funcargs);

    return retValue;
}
public static  uint NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect)
{
    uint oldProtect = 0;
    object[] funcargs =
    {
    processHandle, baseAddress, regionSize, newProtect, oldProtect
};

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("D6B1F4A92254AE1F9C0F95A93C4EDD39", typeof(Delegate.NtProtectVirtualMemory), ref funcargs);

    if (retValue != Data.Native.NTSTATUS.Success)
        throw new InvalidOperationException("Failed to change memory protection, " + retValue);

    oldProtect = (uint)funcargs[4];
    return oldProtect;
}


public static  uint NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength)
{
    uint bytesWritten = 0;
    object[] funcargs =
    {
    processHandle, baseAddress, buffer, bufferLength, bytesWritten
};

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("7E4050B287BB88AA70DF57EF924837E4", typeof(Delegate.NtWriteVirtualMemory), ref funcargs);

    if (retValue != Data.Native.NTSTATUS.Success)
        throw new InvalidOperationException("Failed to write memory, " + retValue);

    bytesWritten = (uint)funcargs[4];
    return bytesWritten;
}


public static  UInt32 NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, ref UInt32 NumberOfBytesToRead)
{
    // Craft an array for the arguments
    UInt32 NumberOfBytesRead = 0;
    object[] funcargs =
    {
        ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead
    };

    Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("F15C5EE126EA79DCA5C232DED0A762D7", typeof(Delegate.NtReadVirtualMemory), ref funcargs);
    if (retValue != Data.Native.NTSTATUS.Success)
    {
        throw new InvalidOperationException("Failed to read memory, " + retValue);
    }

    NumberOfBytesRead = (UInt32)funcargs[4];
    return NumberOfBytesRead;
}



public static  IntPtr NtOpenFile(ref IntPtr fileHandle, Data.Win32.Kernel32.FileAccessFlags desiredAccess, ref Data.Native.OBJECT_ATTRIBUTES objectAttributes, ref Data.Native.IO_STATUS_BLOCK ioStatusBlock, Data.Win32.Kernel32.FileShareFlags shareAccess, Data.Win32.Kernel32.FileOpenFlags openOptions)
{
    object[] funcargs =
    {
    fileHandle, desiredAccess, objectAttributes, ioStatusBlock, shareAccess, openOptions
};

    var retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("CFCE31575F253E4A98F8F207643518D7", typeof(Delegate.NtOpenFile), ref funcargs);

    if (retValue != Data.Native.NTSTATUS.Success)
        throw new InvalidOperationException("Failed to open file, " + retValue);

    fileHandle = (IntPtr)funcargs[0];
    return fileHandle;
}




public static  Data.Native.NTSTATUS NtOpenThread(
    ref System.IntPtr ThreadHandle,
    int DesiredAccess,
    ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
    ref Data.Native.CLIENT_ID ClientId)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ThreadHandle, DesiredAccess, ObjectAttributes, ClientId
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("B2D3E86BD37583AE5AECEAFE7B64FBA7", typeof(Delegate.NtOpenThread), ref funcargs);

		ClientId = (Data.Native.CLIENT_ID) funcargs[3];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtQueueApcThread(
    System.IntPtr ThreadHandle,
    // KNORMAL_ROUTINE
    IntPtr ApcRoutine,
    System.IntPtr ApcArgument1,
    System.IntPtr ApcArgument2,
    System.IntPtr ApcArgument3)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("28EAB5FD6FAF15DF2956DF6F9A3239FC", typeof(Delegate.NtQueueApcThread), ref funcargs);

		

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtOpenSection(
    ref System.IntPtr SectionHandle,
    int DesiredAccess,
    ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			SectionHandle, DesiredAccess, ObjectAttributes
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("B8A85BA6A3C81C0C9794542AF16685C6", typeof(Delegate.NtOpenSection), ref funcargs);

		ObjectAttributes = (Data.Native.OBJECT_ATTRIBUTES) funcargs[2];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtSuspendThread(
    System.IntPtr ThreadHandle,
    ref int PreviousSuspendCount)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ThreadHandle, PreviousSuspendCount
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("C75DF01B52B9AC7C25D72C6F6C1B3F67", typeof(Delegate.NtSuspendThread), ref funcargs);

		PreviousSuspendCount = (int) funcargs[1];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtQueryInformationFile(
    System.IntPtr FileHandle,
    ref Data.Native.IO_STATUS_BLOCK IoStatusBlock,
    System.IntPtr FileInformation,
    int Length,
    Data.Native.FILE_INFORMATION_CLASS FileInformationClass)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("0828DE7F7C570C50F817C1770A18FBEF", typeof(Delegate.NtQueryInformationFile), ref funcargs);

		IoStatusBlock = (Data.Native.IO_STATUS_BLOCK) funcargs[1];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtSetContextThread(
    System.IntPtr ThreadHandle,
    ref Data.Native.CONTEXT Context)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ThreadHandle, Context
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("3E3B673EF650CF9B394EFAD7A5EF6AE9", typeof(Delegate.NtSetContextThread), ref funcargs);

		Context = (Data.Native.CONTEXT) funcargs[1];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtResumeProcess(
    System.IntPtr ProcessHandle)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ProcessHandle
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("C1277262D6EF7AA03C730F57CFE56291", typeof(Delegate.NtResumeProcess), ref funcargs);

		

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtOpenProcessToken(
    System.IntPtr ProcessHandle,
    int DesiredAccess,
    ref System.IntPtr TokenHandle)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ProcessHandle, DesiredAccess, TokenHandle
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("880FB775033932C013E64F3A635E4239", typeof(Delegate.NtOpenProcessToken), ref funcargs);

		TokenHandle = (System.IntPtr) funcargs[2];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtWaitForMultipleObjects(
    int Count,
    ref System.IntPtr Handles,
    Data.Native.WAIT_TYPE WaitType,
    byte Alertable,
    ref Data.Native.LARGE_INTEGER Timeout)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			Count, Handles, WaitType, Alertable, Timeout
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("323092F107AB25DEAD4FA3AAB39CCA1F", typeof(Delegate.NtWaitForMultipleObjects), ref funcargs);

		Timeout = (Data.Native.LARGE_INTEGER) funcargs[4];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtQueryDirectoryFile(
    System.IntPtr FileHandle,
    System.IntPtr Event,
    // PIO_APC_ROUTINE
    IntPtr ApcRoutine,
    System.IntPtr ApcContext,
    ref Data.Native.IO_STATUS_BLOCK IoStatusBlock,
    System.IntPtr FileInformation,
    int Length,
    Data.Native.FILE_INFORMATION_CLASS FileInformationClass,
    byte ReturnSingleEntry,
    ref Data.Native.UNICODE_STRING FileName,
    byte RestartScan)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("10042EFA6BBAF8C40C2D954F441ABD51", typeof(Delegate.NtQueryDirectoryFile), ref funcargs);

		FileName = (Data.Native.UNICODE_STRING) funcargs[9];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtAdjustPrivilegesToken(
    System.IntPtr TokenHandle,
    byte DisableAllPrivileges,
    ref Data.Native.TOKEN_PRIVILEGES NewState,
    int BufferLength,
    ref Data.Native.TOKEN_PRIVILEGES PreviousState,
    ref int ReturnLength)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("64A319E9E2975192B4B10AB3BF384D6D", typeof(Delegate.NtAdjustPrivilegesToken), ref funcargs);

		ReturnLength = (int) funcargs[5];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtQuerySystemInformation(
    Data.Native.SYSTEM_INFORMATION_CLASS SystemInformationClass,
    System.IntPtr SystemInformation,
    int SystemInformationLength,
    ref int ReturnLength)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("DFAB5D148A4E29E720510FFB7148E172", typeof(Delegate.NtQuerySystemInformation), ref funcargs);

		ReturnLength = (int) funcargs[3];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtDeviceIoControlFile(
    System.IntPtr FileHandle,
    System.IntPtr Event,
    // PIO_APC_ROUTINE
    IntPtr ApcRoutine,
    System.IntPtr ApcContext,
    ref Data.Native.IO_STATUS_BLOCK IoStatusBlock,
    int IoControlCode,
    System.IntPtr InputBuffer,
    int InputBufferLength,
    System.IntPtr OutputBuffer,
    int OutputBufferLength)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("537C3CB6BE61CC8FF90F5B97BB3C19C7", typeof(Delegate.NtDeviceIoControlFile), ref funcargs);

		IoStatusBlock = (Data.Native.IO_STATUS_BLOCK) funcargs[4];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtResumeThread(
    System.IntPtr ThreadHandle,
    ref int PreviousSuspendCount)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ThreadHandle, PreviousSuspendCount
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("F0B9EC790542C0858E369EE98817A97D", typeof(Delegate.NtResumeThread), ref funcargs);

		PreviousSuspendCount = (int) funcargs[1];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtCreateProcess(
    ref System.IntPtr ProcessHandle,
    int DesiredAccess,
    ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
    System.IntPtr ParentProcess,
    byte InheritObjectTable,
    System.IntPtr SectionHandle,
    System.IntPtr DebugPort,
    System.IntPtr ExceptionPort)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("3169613184CB4B3AB16A95CA47217BDC", typeof(Delegate.NtCreateProcess), ref funcargs);

		ObjectAttributes = (Data.Native.OBJECT_ATTRIBUTES) funcargs[2];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtSuspendProcess(
    System.IntPtr ProcessHandle)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ProcessHandle
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("30B3F5E0BD1D4C88F52918D7D35913E5", typeof(Delegate.NtSuspendProcess), ref funcargs);

		

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtGetContextThread(
    System.IntPtr ThreadHandle,
    ref Data.Native.CONTEXT ThreadContext)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ThreadHandle, ThreadContext
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("A8D9B301362DC66F5D40D61645446A92", typeof(Delegate.NtGetContextThread), ref funcargs);

		ThreadContext = (Data.Native.CONTEXT) funcargs[1];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtClose(
    System.IntPtr Handle)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			Handle
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("71F57C417B5CD486491837E7582C0931", typeof(Delegate.NtClose), ref funcargs);

		

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtQueryInformationThread(
    System.IntPtr ThreadHandle,
    Data.Native.THREADINFOCLASS ThreadInformationClass,
    System.IntPtr ThreadInformation,
    int ThreadInformationLength,
    ref int ReturnLength)
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("EBAC54AFCBBAD4DB96DF117C91D80D3C", typeof(Delegate.NtQueryInformationThread), ref funcargs);

		ReturnLength = (int) funcargs[4];

		return retValue;
	}
		


public static  Data.Native.NTSTATUS NtTestAlert()
	{  
		// Craft an array for the arguments
		object[] funcargs =
		{
			
		};

		Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)DynamicSysInvoke.DynamicSyscallInvoke("E0860F9E68F5A8FC12D504BD2CC28B80", typeof(Delegate.NtTestAlert), ref funcargs);

		

		return retValue;
	}
		





    }
}
