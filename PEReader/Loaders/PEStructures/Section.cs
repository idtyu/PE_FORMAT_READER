using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Loaders.PEStructures ;

namespace Loaders
{
    public class Section
    {
        public struct section
        {
            public SectionHeader.IMAGE_SECTION_TABLE header;
            public UInt32 import;
           // public LinkedList<Import.Hint_name_table> importName;
            public LinkedList<Import.Hint_name_table> importAddr;
            public LinkedList<Import.Import_Directory_Table> importDirTable;
            public UInt32 export;
            public Export.IMAGE_EXPORT_DIRECTORY exportDirectory;
            public Export.Export_Functions[] functions;
            public UInt32 rvaToOffset;
        }
    }
}
