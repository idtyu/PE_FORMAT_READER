using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Loaders.PEStructures
{
    public class Import
    {
        public struct Import_Directory_Table
        {
            public int id;
            public UInt32 OriginalFirstThunk;
            public UInt32 TimeDateStamp;
            public UInt32 ForwarderChain;
            public string Name1;
            public UInt32 FirstThunk;
            public UInt32 ImportAddressTableOffset;
            public UInt32 ImportNameTableOffset;
            public UInt32 rawOffset;
            public UInt32 RVA;
            public UInt64 VA;
        }
       
        public struct Hint_name_table
        {
            public int id;
            public UInt32 fileOffset;
            public UInt16 hint;
            public string name;
            public bool importByName ;
            public UInt32 rawOffset;
            public UInt32 RVA;
            public UInt64 VA;
        }
    }
}