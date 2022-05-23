// DInvoke delegates taken from https://github.com/TheWover/DInvoke/blob/15924897d9992ae90ec43aaf3b74915df3e4518b/DInvoke/DInvoke/DynamicInvoke/Native.cs
// Additional delegates generated with https://github.com/jaredpar/pinvoke-interop-assistant
using System;

// Delegates
using System.Runtime.InteropServices;

// Data types
using Data = SharpWhispers.Data;

namespace Delegates
{
    class SyscallDelegates
    {
		/* Delegates */

	public struct Delegate
	{

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtCreateThreadEx(
	out IntPtr threadHandle,
	Data.Win32.WinNT.ACCESS_MASK desiredAccess,
	IntPtr objectAttributes,
	IntPtr processHandle,
	IntPtr startAddress,
	IntPtr parameter,
	bool createSuspended,
	int stackZeroBits,
	int sizeOfStack,
	int maximumStackSize,
	IntPtr attributeList);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtCreateSection(
	ref IntPtr SectionHandle,
	uint DesiredAccess,
	IntPtr ObjectAttributes,
	ref ulong MaximumSize,
	uint SectionPageProtection,
	uint AllocationAttributes,
	IntPtr FileHandle);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtUnmapViewOfSection(
	IntPtr hProc,
	IntPtr baseAddr);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtMapViewOfSection(
	IntPtr SectionHandle,
	IntPtr ProcessHandle,
	out IntPtr BaseAddress,
	IntPtr ZeroBits,
	IntPtr CommitSize,
	IntPtr SectionOffset,
	out ulong ViewSize,
	uint InheritDisposition,
	uint AllocationType,
	uint Win32Protect);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtQueryInformationProcess(
	IntPtr processHandle,
	Data.Native.PROCESSINFOCLASS processInformationClass,
	IntPtr processInformation,
	int processInformationLength,
	ref UInt32 returnLength);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtOpenProcess(
	ref IntPtr ProcessHandle,
	Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
	ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
	ref Data.Native.CLIENT_ID ClientId);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtAllocateVirtualMemory(
	IntPtr ProcessHandle,
	ref IntPtr BaseAddress,
	IntPtr ZeroBits,
	ref IntPtr RegionSize,
	UInt32 AllocationType,
	UInt32 Protect);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtFreeVirtualMemory(
	IntPtr ProcessHandle,
	ref IntPtr BaseAddress,
	ref IntPtr RegionSize,
	UInt32 FreeType);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtQueryVirtualMemory(
	IntPtr ProcessHandle,
	IntPtr BaseAddress,
	Data.Native.MEMORYINFOCLASS MemoryInformationClass,
	IntPtr MemoryInformation,
	UInt32 MemoryInformationLength,
	ref UInt32 ReturnLength);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtProtectVirtualMemory(
	IntPtr ProcessHandle,
	ref IntPtr BaseAddress,
	ref IntPtr RegionSize,
	UInt32 NewProtect,
	ref UInt32 OldProtect);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtWriteVirtualMemory(
	IntPtr ProcessHandle,
	IntPtr BaseAddress,
	IntPtr Buffer,
	UInt32 BufferLength,
	ref UInt32 BytesWritten);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtReadVirtualMemory(
	IntPtr ProcessHandle,
	IntPtr BaseAddress,
	IntPtr Buffer,
	UInt32 NumberOfBytesToRead,
	ref UInt32 NumberOfBytesRead);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtOpenFile(
	ref IntPtr FileHandle,
	Data.Win32.Kernel32.FileAccessFlags DesiredAccess,
	ref Data.Native.OBJECT_ATTRIBUTES ObjAttr,
	ref Data.Native.IO_STATUS_BLOCK IoStatusBlock,
	Data.Win32.Kernel32.FileShareFlags ShareAccess,
	Data.Win32.Kernel32.FileOpenFlags OpenOptions);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtOpenThread(
	ref System.IntPtr ThreadHandle,
	int DesiredAccess,
	ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
	ref Data.Native.CLIENT_ID ClientId);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtQueueApcThread(
	System.IntPtr ThreadHandle,
	IntPtr ApcRoutine,
	System.IntPtr ApcArgument1,
	System.IntPtr ApcArgument2,
	System.IntPtr ApcArgument3);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtOpenSection(
	ref System.IntPtr SectionHandle,
	int DesiredAccess,
	ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtSuspendThread(
	System.IntPtr ThreadHandle,
	ref int PreviousSuspendCount);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtQueryInformationFile(
	System.IntPtr FileHandle,
	ref Data.Native.IO_STATUS_BLOCK IoStatusBlock,
	System.IntPtr FileInformation,
	int Length,
	Data.Native.FILE_INFORMATION_CLASS FileInformationClass);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtSetContextThread(
	System.IntPtr ThreadHandle,
	ref Data.Native.CONTEXT Context);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtResumeProcess(
	System.IntPtr ProcessHandle);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtOpenProcessToken(
	System.IntPtr ProcessHandle,
	int DesiredAccess,
	ref System.IntPtr TokenHandle);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtWaitForMultipleObjects(
	int Count,
	ref System.IntPtr Handles,
	Data.Native.WAIT_TYPE WaitType,
	byte Alertable,
	ref Data.Native.LARGE_INTEGER Timeout);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtQueryDirectoryFile(
	System.IntPtr FileHandle,
	System.IntPtr Event,
	IntPtr ApcRoutine,
	System.IntPtr ApcContext,
	ref Data.Native.IO_STATUS_BLOCK IoStatusBlock,
	System.IntPtr FileInformation,
	int Length,
	Data.Native.FILE_INFORMATION_CLASS FileInformationClass,
	byte ReturnSingleEntry,
	ref Data.Native.UNICODE_STRING FileName,
	byte RestartScan);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtAdjustPrivilegesToken(
	System.IntPtr TokenHandle,
	byte DisableAllPrivileges,
	ref Data.Native.TOKEN_PRIVILEGES NewState,
	int BufferLength,
	ref Data.Native.TOKEN_PRIVILEGES PreviousState,
	ref int ReturnLength);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtQuerySystemInformation(
	Data.Native.SYSTEM_INFORMATION_CLASS SystemInformationClass,
	System.IntPtr SystemInformation,
	int SystemInformationLength,
	ref int ReturnLength);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtDeviceIoControlFile(
	System.IntPtr FileHandle,
	System.IntPtr Event,
	IntPtr ApcRoutine,
	System.IntPtr ApcContext,
	ref Data.Native.IO_STATUS_BLOCK IoStatusBlock,
	int IoControlCode,
	System.IntPtr InputBuffer,
	int InputBufferLength,
	System.IntPtr OutputBuffer,
	int OutputBufferLength);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtResumeThread(
	System.IntPtr ThreadHandle,
	ref int PreviousSuspendCount);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtCreateProcess(
	ref System.IntPtr ProcessHandle,
	int DesiredAccess,
	ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
	System.IntPtr ParentProcess,
	byte InheritObjectTable,
	System.IntPtr SectionHandle,
	System.IntPtr DebugPort,
	System.IntPtr ExceptionPort);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtSuspendProcess(
	System.IntPtr ProcessHandle);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtGetContextThread(
	System.IntPtr ThreadHandle,
	ref Data.Native.CONTEXT ThreadContext);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtClose(
	System.IntPtr Handle);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtQueryInformationThread(
	System.IntPtr ThreadHandle,
	Data.Native.THREADINFOCLASS ThreadInformationClass,
	System.IntPtr ThreadInformation,
	int ThreadInformationLength,
	ref int ReturnLength);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate Data.Native.NTSTATUS NtTestAlert();


            
        }
    }
}
