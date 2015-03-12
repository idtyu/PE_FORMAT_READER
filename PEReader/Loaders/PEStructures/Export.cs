using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Loaders.PEStructures
{
    public class Export
    {
        public struct IMAGE_EXPORT_DIRECTORY
        {
           
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public string nName;
            public UInt32 nBase;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions; //Array of Export Address Table
            public UInt32 AddressOfNames; //Array of Export Name Table
            public UInt32 AddressOfNameOrdinals; //Array of Export Ordinal Table
        }

        public struct Export_Functions
        {
            public UInt32 RVA;
            public UInt32 RVARawOffset;
            public UInt32 RVARVA;
            public UInt64 RVAVA;
            public UInt16 ordinal;
            public UInt32 ordinalRawOffset;
            public UInt32 ordinalRVA;
            public UInt64 ordinalVA;
            public string name;
            public UInt32 nameRawOffset;
            public UInt32 nameRVA;
            public UInt64 nameVA;
        }


    }
}
