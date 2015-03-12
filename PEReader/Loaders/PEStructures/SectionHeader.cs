using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Loaders
{
    public class SectionHeader
    {
        public struct IMAGE_SECTION_TABLE
        {
            public UInt64 Name;
            public UInt32 VirtualSize;
            public UInt32 VirtualAddress;
            public UInt32 SizeOfRawData;
            public UInt32 PointerToRawData;
            public UInt32 PointerToRelocations;
            public UInt32 PointerToLineNumbers;
            public UInt16 NumberOfRelocations;
            public UInt16 NumberOfLinenumbers;
            public UInt32 Characteristics;
        }

    }
}
