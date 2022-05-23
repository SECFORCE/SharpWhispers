// https://github.com/rasta-mouse/DInvoke/blob/master/DInvoke.Data/PE.cs
using System;
using System.Runtime.InteropServices;

namespace SharpWhispers.Data
{
    /// <summary>
    /// Holds data structures for using PEs.
    /// </summary>
    public static class PE
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public Native.LIST_ENTRY InLoadOrderLinks;
            public Native.LIST_ENTRY InMemoryOrderLinks;
            public Native.LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public Native.UNICODE_STRING FullDllName;
            public Native.UNICODE_STRING BaseDllName;
        }
    }
}
