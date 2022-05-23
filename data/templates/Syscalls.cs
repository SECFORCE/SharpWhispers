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
        
        <FUNCTION_HELPERS>


    }
}
