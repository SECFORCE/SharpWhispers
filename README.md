# SharpWhispers

![LOGO](logo.png)

C# porting of [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2).

It uses [SharpASM](https://github.com/SECFORCE/SharpASM) to find the code caves for executing the system call stub.

Read the blog post for the technical details: [https://www.secforce.com/blog/sharpasm-sharpwhispers/](https://www.secforce.com/blog/sharpasm-sharpwhispers/)



# Requirements

- Visual Studio
- .NET Framework >= 3.5
- Python3


# Usage

```

   ______               _      ____   _                    
  / __/ /  ___ ________| | /| / / /  (_)__ ___  ___ _______
 _\ \/ _ \/ _ `/ __/ _ \ |/ |/ / _ \/ (_-</ _ \/ -_) __(_-<
/___/_//_/\_,_/_/ / .__/__/|__/_//_/_/___/ .__/\__/_/ /___/
                 /_/                    /_/                

@d_glenx
@SECFORCE_LTD

=============================================================


usage: SharpWhispers.py [-h] [-p PRESET] [-f FUNCTIONS] -o OUT_FILE

optional arguments:
  -h, --help            show this help message and exit
  -p PRESET, --preset PRESET
                        Preset ("all", "common", "dinvoke")
  -f FUNCTIONS, --functions FUNCTIONS
                        Comma-separated functions
  -o OUT_FILE, --out-file OUT_FILE
                        Output basename (w/o extension)

```

The instructions to create the Visual Studio project are provided [here](./examples/Usage.md)

A basic process injection example is provided [here](./examples/BasicProcessInjection.md)

## Presets

At the moment the json files contains the data to generate 33 system calls.

**Note: the `All` preset contains a subset of all the system calls.**

### All

```
==== System Calls Imported ====

==[DInvoke]==
[i] Number of Delegates: 13

NtCreateThreadEx
NtCreateSection
NtUnmapViewOfSection
NtMapViewOfSection
NtQueryInformationProcess
NtOpenProcess
NtAllocateVirtualMemory
NtFreeVirtualMemory
NtQueryVirtualMemory
NtProtectVirtualMemory
NtWriteVirtualMemory
NtReadVirtualMemory
NtOpenFile

==[Additional]==
[i] Number of Delegates: 20

NtOpenThread
NtQueueApcThread
NtOpenSection
NtSuspendThread
NtQueryInformationFile
NtSetContextThread
NtResumeProcess
NtOpenProcessToken
NtWaitForMultipleObjects
NtQueryDirectoryFile
NtAdjustPrivilegesToken
NtQuerySystemInformation
NtDeviceIoControlFile
NtResumeThread
NtCreateProcess
NtSuspendProcess
NtGetContextThread
NtClose
NtQueryInformationThread
NtTestAlert
```

### Common

```
NtCreateThreadEx
NtCreateSection
NtUnmapViewOfSection
NtMapViewOfSection
NtQueryInformationProcess
NtAllocateVirtualMemory
NtFreeVirtualMemory
NtProtectVirtualMemory
NtWriteVirtualMemory
NtOpenFile
NtReadVirtualMemory
NtQueryVirtualMemory
NtOpenProcess
```

### DInvoke

```
NtCreateThreadEx
NtCreateSection
NtUnmapViewOfSection
NtMapViewOfSection
NtQueryInformationProcess
NtOpenProcess
NtAllocateVirtualMemory
NtFreeVirtualMemory
NtQueryVirtualMemory
NtProtectVirtualMemory
NtWriteVirtualMemory
NtReadVirtualMemory
NtOpenFile
```





# Templates

## Delegates.cs

**Dynamically Generated**

Contains the delegates of the system calls to generate

## PEB.cs

*Depends on SharpASM*

Helper to get the address of PEB using ASM 

## SharpASM.cs

Contains the code to dynamically call ASM in c#.
The function `public static IntPtr callASM(byte[] stub)` can be used to call the shellcode passing a byte array.

## SharpWhispers.cs

**Dynamically Generated - The script generates a random seed to hash the system call names**

Contains the code to retrieve the system call numbers using [ElephantSe4l](https://twitter.com/elephantse4l)'s [technique](https://www.crummie5.club/freshycalls/) (code ported from [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)).

## Syscalls.cs

*Depends on SharpASM*

Contains the code to execute the system calls dynamically using ASM.

Contains also the wrappers for the system calls (e.g. `Syscall.NtAllocateVirtualMemory`) (**Dynamically Generated**)


## DInvoke Data types

**Dynamically Generated**

SharpWhispers output files can be used directly into a C# project. The needed data types are a subset of the data types defined in the [DInvoke project](https://github.com/TheWover/DInvoke/tree/main/DInvoke/DInvoke) (some data types are actually borrowed form [Rastamouse's minimized project](https://github.com/rasta-mouse/DInvoke)) so as to reduce the detection surface. The data types are defined in the `SharpWhisper.Data` namspace to avoid overlapping with DInvoke's definitions.


**Note:** The data types are generated only if needed (i.e. if a system call needs a data type) to minimize the detection surface.


The following templates are used to generate the needed data types:

- TypedefsNative.cs
- TypedefsPE.cs
- TypedefsWin32.cs

