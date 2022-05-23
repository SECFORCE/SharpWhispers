// Author: Dimitri (GlenX) Di Cristofaro (@d_glenx)
// This project uses Conditional Compilation Symbols to handle 32/64 bit compilation.
// In case Conditional Compilation Symbols are not set, this variable should be manually defined for 64 bit
//#define WIN64
using System;
using System.Runtime.InteropServices;


namespace SharpAssembly
{
	class SharpASM
	{
		/* DLL Imports */
/*
		// we hardcoded the values so we don't need to call GetSystemInfo
		[DllImport("kernel32.dll")]
		static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
*/
		/* We need VirtualQueryEx to enumerate the memory address space for RWX regions */
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

		// after 5 subsequent failed calls it will stop re-trying
		static private uint failed_calls = 0;
		static private uint MAX_FAILED_CALLS = 5;

		public struct Delegates
		{
			[UnmanagedFunctionPointer(CallingConvention.StdCall)]
			public delegate IntPtr stubDelegate();
		}

#if WIN64
		public static Int64 PtrToInt(IntPtr ptr)
		{
			return ptr.ToInt64();
		}
#else
		public static Int32 PtrToInt(IntPtr ptr)
		{
			return ptr.ToInt32();
		}
#endif



		public static object DynamicFunctionInvoke(IntPtr functionPointer, Type functionDelegateType, ref object[] parameters)
		{
			var funcDelegate = Marshal.GetDelegateForFunctionPointer(functionPointer, functionDelegateType);
			IntPtr ret = IntPtr.Zero;

			// We don't catch the exceptions here 
			// we want to propagate the exceptions to the caller
			// so that we can handle them properly
			/*
			try
			{
				var res = funcDelegate.DynamicInvoke(parameters);
				ret = (IntPtr)res;
			}
			catch (Exception e)
			{
				Console.WriteLine("Error!");
				Console.WriteLine("{0}", e);
			}
			*/

			var res = funcDelegate.DynamicInvoke(parameters);
			ret = (IntPtr)res;

			return ret;
		}



		// VirtualQuery() results
		[StructLayout(LayoutKind.Sequential)]
		public struct MEMORY_BASIC_INFORMATION
		{
			public UIntPtr BaseAddress;
			public UIntPtr AllocationBase;
			public uint AllocationProtect;
			public IntPtr RegionSize;
			public uint State;
			public uint Protect;
			public int Type;
		}

		/*
		// GetSystemInfo() results
		// We don't need it because we hardcoded the values
		public struct SYSTEM_INFO
		{
			public ushort processorArchitecture;
			ushort reserved;
			public uint pageSize;
			public IntPtr minimumApplicationAddress;
			public IntPtr maximumApplicationAddress;
			public IntPtr activeProcessorMask;
			public uint numberOfProcessors;
			public uint processorType;
			public uint allocationGranularity;
			public ushort processorLevel;
			public ushort processorRevision;
		}
		*/

		// return true if the pointer is aligned
		public static bool isPtrAligned(IntPtr ptr)
		{

			// We want to be aligned to
			// - 8 bytes (64 bit) bit for x86 [32 bit]
			// - 16 bytes (128 bit) for x86-64 [64 bit]

			var ptr_int = PtrToInt(ptr);

#if !WIN64
			if (ptr_int % 8 == 0) return true;
#else
			if (ptr_int % 16 == 0) return true;
#endif
			else return false;
		}




		// return the aligned pointer
		// it will verify that there is a buffer of 0s between the aligned address (alignedPtr) and the original one (ptr)
		// return -1 if it can't find the 0-sequence
		public static IntPtr AlignPtr(IntPtr ptr)
		{
			// Strategy
			// Start from the aligned address alignedPtr
			// Verify that all the values between alignedPtr and ptr are 0s


			var ptr_int = PtrToInt(ptr);

#if !WIN64
			Int32 offset = 0;
#else
			Int64 offset = 0;
#endif
			// We want to be aligned to
			// - 8 bytes (64 bit) bit for x86 [32 bit]
			// - 16 bytes (128 bit) for x86-64 [64 bit]
#if !WIN64
			offset = ptr_int % 8;
#else
			offset = ptr_int % 16;
#endif

			IntPtr alignedPtr = new IntPtr(ptr_int - offset);

			// scan sequence
			unsafe
			{
				byte* array = (byte*)alignedPtr;
				for (int i = 1; ; ++i)
				{
					if (i == offset)
					{ // full sequence matched?
						return (IntPtr)(array);
					}
					else if (array[i] != 0)
					{
						break;
					}
				}
			}

			// We didn't find the 0 sequence, we have to search another area
			return new IntPtr(-1);
		}


		// Edited from: https://stackoverflow.com/questions/25400610/most-efficient-way-to-find-pattern-in-byte-array/39021296
		/// <summary>
		/// Looks for the next occurrence of a 0-sequence in a byte array starting from the end and searching backwards.
		/// It will search for a memory area that is aligned and returns the address of the start of the buffer
		/// </summary>
		/// <param name="addr">Address of the region to scan</param>
		/// <param name="regionLength">Length of the region to scan</param>
		/// <param name="patternLength">Length of the pattern to find</param>
		/// <returns>
		///   The address of the first 0 or null if not found
		///   The address is aligned to
		///   - 64 bits for x86 [32 bit]
		///   - 128 bits for x86-64 [64 bit]
		/// </returns>
		public static IntPtr GetZeroSequence(IntPtr addr, IntPtr regionLength, uint patternLength)
		{
			Console.WriteLine("[i] Searching sequence of " + patternLength + " NULL bytes to host the stub...");

			// We will start searching from the end
			Int64 end = (Int64)regionLength - 1; // past here no match is possible
			uint start = 0;
			int offset = 1;
			unsafe
			{
				byte* array = (byte*)addr;

				while (start <= end)
				{
					// scan for first byte only. compiler-friendly.
					if (array[end] == 0)
					{
						// scan for rest of sequence
						for (offset = 1; ; ++offset)
						{
							if (offset == patternLength)
							{ // full sequence matched?

							  // Verify aligment
								IntPtr retPtr = (IntPtr)(array + end - offset);
								if (! isPtrAligned(retPtr))
								{
									retPtr = AlignPtr(retPtr);
									// if -1 is returned, it means that we didn't find enough 0s to be aligned
									// We have to continue to search
									if (retPtr.Equals(-1)) break;
								}

								// The start address is aligned
								return retPtr;


							}
							else if (array[end - offset] != 0)
							{
								break;
							}
						}
					}

					// If we arrive here, either
					// we found a value != 0 at array[end - offset]
					// or
					// the pointer was not aligned
					end = end - offset;
				}

			}

			return IntPtr.Zero;
		}


		public struct Constant
		{
			// Mem Type constants
			public const uint MEM_COMMIT = 0x1000;
			public const uint MEM_RESERVE = 0x2000;
			public const uint MEM_RELEASE = 0x8000;

			// Page Constants
			public const uint PAGE_READONLY = 0x02;
			public const uint PAGE_READWRITE = 0x04;
			public const uint PAGE_EXECUTE = 0x10;
			public const uint PAGE_EXECUTE_READ = 0x20;
			public const uint PAGE_EXECUTE_READWRITE = 0x40;

			public const uint SEC_IMAGE = 0x1000000;
		}


		public static IntPtr previous_addr = IntPtr.Zero;

		public static bool isPrevious(IntPtr addr)
		{
			if (addr == previous_addr) return true;
			
			previous_addr = addr;

			return false;
		}

		// Find a Code Cave
		public static IntPtr FindRWX(uint len)
		{
			// https://codereview.stackexchange.com/questions/243292/c-class-to-dump-the-memory-of-a-process-in-several-formats
			// https://codingvision.net/c-how-to-scan-a-process-memory

			IntPtr caveAddr = IntPtr.Zero;

			// getting minimum & maximum address
			// NB: The values are *often*
			// Min: 0x1000
			// Max (x64): 0x7FFFFFFEFFFF 
			// Max (x86): 0x7ffeffff
			

			// The values are hardcoded to remove the call to GetSystemInfo()
			/*
			SYSTEM_INFO sys_info = new SYSTEM_INFO();
			GetSystemInfo(out sys_info);

			IntPtr proc_min_address = sys_info.minimumApplicationAddress;
			IntPtr proc_max_address = sys_info.maximumApplicationAddress;
			*/


			IntPtr proc_min_address = new IntPtr(0x1000);

#if WIN64
			IntPtr proc_max_address = new IntPtr(0x7FFFFFFEFFFF);
#else
			IntPtr proc_max_address = new IntPtr(0x7ffeffff);
#endif


			// saving the values as long ints so I won't have to do a lot of casts later
			var proc_min_address_l = PtrToInt(proc_min_address);
			var proc_max_address_l = PtrToInt(proc_max_address);


			// opening the process with desired access level
			IntPtr processHandle = (IntPtr)(-1);

			// this will store any information we get from VirtualQueryEx()
			MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

			//Console.WriteLine("[i] Searching RWX region to host the asm stub");

			while (proc_min_address_l < proc_max_address_l)
			{
				// 28 = sizeof(MEMORY_BASIC_INFORMATION)
				if(VirtualQueryEx(processHandle, proc_min_address, out mem_basic_info, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0)
				{
					// Error in VirtualQueryEx - Get another page
					// move to the next memory chunk
					proc_min_address_l += PtrToInt(mem_basic_info.RegionSize);
					proc_min_address = new IntPtr(proc_min_address_l);
					continue;
				}


				// if this memory chunk is accessible and RWX
				if (mem_basic_info.State == Constant.MEM_COMMIT && mem_basic_info.Protect == Constant.PAGE_EXECUTE_READWRITE)
				{
					Console.WriteLine("[i] Found RWX Region!");
					Console.WriteLine("[>] Address : " + string.Format("{0:X}", PtrToInt(proc_min_address)));
					//Console.WriteLine("[>] Size : " + string.Format("{0:X}", PtrToInt(mem_basic_info.RegionSize)));

					if (PtrToInt(mem_basic_info.RegionSize) >= len)
					{
						// Check if the memory area has been used in the previous execution
						if (isPrevious(proc_min_address))
						{
							Console.WriteLine("Memory area used for the previous code cave.. Skipping");
							// move to the next memory chunk
							proc_min_address_l += PtrToInt(mem_basic_info.RegionSize);
							proc_min_address = new IntPtr(proc_min_address_l);
							continue;
						}

						// Search for enough 0s starting from the end of the page
						// This will decrease the likelihood that the region hosting our stub will be overridden before we execute it
						caveAddr = GetZeroSequence(proc_min_address, mem_basic_info.RegionSize, len);
						
						IntPtr failed = new IntPtr(-1);
						if (caveAddr != IntPtr.Zero && caveAddr != failed)
						{
							Console.WriteLine("[>] Sequence of 0s Found : " + string.Format("{0:X}", PtrToInt(caveAddr)));
							return caveAddr;
						}
					}
				}

				// move to the next memory chunk
				proc_min_address_l += PtrToInt(mem_basic_info.RegionSize);
				proc_min_address = new IntPtr(proc_min_address_l);
			}

			Console.WriteLine("Not Found!");

			return IntPtr.Zero;
		}



		// Wrapper to call ASM aka shellcode
		// Return: content of EAX
		// - Search for a RWX region
		// - write the opcodes in the RWX region
		// - Call DynamicFunctionInvoke (System.Delegate.DynamicInvoke)
		// - Cleanup RWX region from the stub
		public static IntPtr callASM(byte[] stub)
		{
			// Check if we failed too much
			if (failed_calls > MAX_FAILED_CALLS) return new IntPtr(-1);

			IntPtr ret = IntPtr.Zero;
			IntPtr pStub = IntPtr.Zero;


			uint stubLen = (uint)stub.Length;

			// no parameters
			object[] parameters = { };

			// Find RWX
			pStub = FindRWX(stubLen);

			if (pStub == IntPtr.Zero)
			{
				Console.WriteLine("Error finding the code cave!");
				return (IntPtr)(-1);
			}

				// Write stub
				unsafe
				{
					byte* ptr = (byte*)pStub;
					for (uint i = 0; i < (uint)stub.Length; i++)
					{
						*(ptr + i) = stub[i];
					}
				}



			Console.WriteLine("ASM Stub written @ 0x" + string.Format("{0:X}", PtrToInt(pStub)));
			

			// If we get an exception, we call ourselves again and retry 
			// Call stub
			try
			{
				ret = (IntPtr)DynamicFunctionInvoke(pStub, typeof(Delegates.stubDelegate), ref parameters);
			}
			catch (Exception e)
			{				
				Console.WriteLine("{0}", e);
				Console.WriteLine("[!] Trying Again...");

				// Increase global counter
				// We set an upper limit to the number of re-tries to avoid potential infite loops
				failed_calls++;

				ret = callASM(stub);

				// We return directly, without deleting the old stub
				// (we are probably leaving junk bytes in the memory hosting the old stub)
				// IMHO this is safer because if the CLR has written something there,
				// we might overwrite something needed and crash the process.
				// During the experiments, leaving the memory dirty didn't seem to be an issue
				//
				// HYPOTHESIS:
				// the CLR doesn't know that pStub is filled with our data
				// so, if it needs that memory, it will probably just overwrite it.
				return ret;
			}





			// Delete Stub
			// Cleanup

			Console.WriteLine("[i] Stub executed! Cleaning the bytes from memory...");

			unsafe
			{
				byte* ptr = (byte*)pStub;
				for (uint i = 0; i < (uint)stub.Length; i++)
				{
					*(ptr + i) = 0x00;
				}
			}

			// If we arrive here, it means that everything went ok
			// We reset the failed calls counter
			failed_calls = 0;

			return ret;
		}

	}
}

