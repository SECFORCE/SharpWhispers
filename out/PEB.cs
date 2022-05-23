// Author: Dimitri (GlenX) Di Cristofaro (@d_glenx)
// This project uses Conditional Compilation Symbols to handle 32/64 bit compilation.
// In case Conditional Compilation Symbols are not set, this variable should be manually defined for 64 bit
//#define WIN64
using System;

using SharpASM = SharpAssembly.SharpASM;

namespace SharpWhispers
{
    class PEB
    {
        // PEB ptr - We will search PEB's address just once
        static IntPtr peb;
#if WIN64
        // __readgsqword(0x60)
        static byte[] bReadgsqword =
        {
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60,     // mov rax, qword ptr gs:[0x60]
            0x00, 0x00, 0x00,
            0xc3                                    // ret
        };
#endif

#if !WIN64
        // __readfsdword(0x30)
        static byte[] bReadfsdword =
        {
            0x55, // push ebp             
            0x8B, 0xEC, // mov ebp,esp
            0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, // mov eax,dword ptr fs:[30]                          
            0x5D, // pop ebp      
            0xC3 // ret
        };
#endif
        public static IntPtr GetPEB()
        {

            if (peb.Equals(IntPtr.Zero))
            {
                Console.WriteLine("Getting PEB using ASM...");
#if WIN64
                peb = SharpASM.callASM(bReadgsqword);
#else

                peb = SharpASM.callASM(bReadfsdword);
#endif

            }
            return peb;
        }
    }
}
