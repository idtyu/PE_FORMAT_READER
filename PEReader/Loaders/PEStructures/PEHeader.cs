using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Loaders
{
    public class PEHeader
    {

        public static Dictionary<UInt32, String> machineType = new Dictionary<UInt32, string>()
       {    {0x0000,"IMAGE_FILE_MACHINE_UNKNOWN"},
            {0x014c,"IMAGE_FILE_MACHINE_I386"} ,
            {0x0200 ,"IMAGE_FILE_MACHINE_IA64 "},
            {0x8664,"IMAGE_FILE_MACHINE_AMD64"} ,
            {0x1d3,"IMAGE_FILE_MACHINE_AM33"} ,
            {0x1c0,"ARM_LITTLE_ENDIAN"} ,
            {0x1c4,"IMAGE_FILE_MACHINE_ARMV7"} ,
            {0x9041,"IMAGE_FILE_MACHINE_M32R"} ,
            {0x266,"IMAGE_FILE_MACHINE_MIPS16"} ,
            {0x366,"IMAGE_FILE_MACHINE_MIPSFPU"},
            {0x466,"IMAGE_FILE_MACHINE_MIPSFPU16"} ,
            {0x1f0,"IMAGE_FILE_MACHINE_POWERPC"} ,
            {0x1f1,"IMAGE_FILE_MACHINE_R4000"} ,
            {0x166,"IMAGE_FILE_MACHINE_POWERPCFP"} ,
            {0x1a2,"IMAGE_FILE_MACHINE_SH3"} ,
            {0x1a3,"IMAGE_FILE_MACHINE_SH3DSP"} ,
            {0x1a6,"IMAGE_FILE_MACHINE_SH4"} ,
            {0x1a8,"IMAGE_FILE_MACHINE_SH5"} ,
            {0x1c2,"IMAGE_FILE_MACHINE_THUMB"} ,
            {0x169,"IMAGE_FILE_MACHINE_WCEMIPSV2"}
        };

        public static Dictionary<string, string> winVersion = new Dictionary<string, string>() {
            {"1.0" ,"Win 1.0"},
            {"2.1" ,"Win 2.0"},
            {"3.0" ,"Win 3.0"},
            {"3.1" ,"Win NT"},
            {"4.0" ,"Win 95"},
            {"4.1" ,"Win 98"},
            {"4.9" ,"Win ME"},
            {"5.0" ,"Win 2000"},
            {"5.1" ,"Win XP"},
            {"5.2","Win 2003"},
            {"6.0" ,"Win Vista"},
            {"6.1" ,"Win 7"},
            {"6.2" ,"Win 8"},
        };

        //0xF000
        public static Dictionary<UInt32, String> charFlag0 = new Dictionary<UInt32, string>()
        {
            {1,"IMAGE_FILE_SYSTEM"},
            {2,"IMAGE_FILE_DLL"},
            {3,"IMAGE_FILE_UP_SYSTEM_ONLY"},
            {4,"IMAGE_FILE_BYTES_REVERSED_HI"},
    
        };
        //0X0F00
        public static Dictionary<UInt32, String> charFlag1 = new Dictionary<UInt32, string>(){
            {1,"IMAGE_FILE_32BIT_MACHINE"},
            {2,"IMAGE_FILE_DEBUG_STRIPPED"},
            {3,"IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP"},
            {4,"IMAGE_FILE_NET_RUN_FROM_SWAP"},

        
        };
        //ox00F0
        public static Dictionary<UInt32, String> charFlag2 = new Dictionary<UInt32, string>(){
            {1,"IMAGE_FILE_AGGRESSIVE_WS_TRIM"},
            {2,"IMAGE_FILE_LARGE_ADDRESS_ AWARE"},
            {3,"Reserved"},
            {4,"IMAGE_FILE_BYTES_REVERSED_LO"},
     
        
        };
        //0x000F
        public static Dictionary<UInt32, String> charFlag3 = new Dictionary<UInt32, string>(){
            {1,"IMAGE_FILE_RELOCS_STRIPPED"},
            {2,"IMAGE_FILE_EXECUTABLE_IMAGE"},
            {3,"IMAGE_FILE_LINE_NUMS_STRIPPED"},
            {4,"IMAGE_FILE_LOCAL_SYMS_STRIPPED"},   
            
        };
        //magic numbers

        public static Dictionary<UInt32, String> magic = new Dictionary<UInt32, string>(){
            {0x010b,"PE32"},
            {0x0107,"ROM image"},
            {0x020b,"PE32+ "}
        };

        public static Dictionary<UInt32, string> subsystem = new Dictionary<UInt32, string>()
        {
            {0,"IMAGE_SUBSYSTEM_UNKNOWN"},
            {1,"IMAGE_SUBSYSTEM_NATIVE"},
            {2,"IMAGE_SUBSYSTEM_WINDOWS_GUI"},
            {3,"IMAGE_SUBSYSTEM_WINDOWS_CUI"},
            {7,"IMAGE_SUBSYSTEM_POSIX_CUI"},
            {9,"IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"},
            {10,"IMAGE_SUBSYSTEM_EFI_APPLICATION"},
            {11,"IMAGE_SUBSYSTEM_EFI_BOOT_ SERVICE_DRIVER"},
            {12,"IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"},
            {13,"IMAGE_SUBSYSTEM_EFI_ROM"},
            {14,"IMAGE_SUBSYSTEM_XBOX"}
        };

        public static Dictionary<UInt32, string> dllChar = new Dictionary<UInt32, string>()
        {
            {0001,"RESERVED"},
            {0002,"RESERVED"},
            {0004,"RESERVED"},
            {0008,"RESERVED"},
            {0000,""},
            {0040,"IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE"},
            {0080,"IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY"},
            {0100,"IMAGE_DLL_CHARACTERISTICS_NX_COMPAT"},
            {0200,"IMAGE_DLLCHARACTERISTICS_ NO_ISOLATION"},
            {0400,"IMAGE_DLLCHARACTERISTICS_ NO_SEH"},
            {0800,"IMAGE_DLLCHARACTERISTICS_ NO_BIND"},
            {1000,"RESERVED"},
            {2000,"IMAGE_DLLCHARACTERISTICS_ WDM_DRIVER"},
            {8000,"IMAGE_DLLCHARACTERISTICS_ TERMINAL_SERVER_AWARE"},
        };      

        public struct IMAGE_DOS_HEADER
        {
            public UInt16 Identifier;  //0x5a 4d
            public UInt16 LastPageSize;   //Bytes on last page of file
            public UInt16 NoOfPages;     //Bytes on last page of file
            public UInt16 RelocationsSize;   //relocation size
            public UInt16 HeaderSize;//size of header
            public UInt16 MinimumExtraPara;//minimum extra data
            public UInt16 MaximumExtraPara;//maximum extra data
            public UInt16 InitialSS; //initial SS
            public UInt16 InitialSP; //initial sp
            public UInt16 Checksum;//checksum
            public UInt16 InitialCS; //initial CS
            public UInt16 InitialIP; //initial IP
            public UInt16 RelocationTable; //relocation table
            public UInt16 OverlayNumber; //over lay number
            public UInt16 studSize;

            public void getStudSize() { studSize = (UInt16)(NoOfPages * 512 - (512 - LastPageSize)); }


        }

        public struct EXTRA_HEADER
        {
            public UInt16 peHeaderLoc;
        }

        public struct IMAGE_FILE_HEADER
        {
            public UInt32 peSig;
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public struct IMAGE_OPTIONAL_HEADER
        {
            public UInt16 Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubSystemVersion;
            public UInt16 MinorSubSystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            public UInt64 data_va;
            public UInt64 code_va;
            public UInt64 entryPtr_va;

        }

        public struct IMAGE_DATA_DIRECTORY
        {
            // ExportTable;
            public UInt32 exportRVA;
            public UInt32 exportSize;
            // ImportTable;
            public UInt32 importRVA;
            public UInt32 importSize;
            // ResourceTable;
            public UInt32 resourceRVA;
            public UInt32 resourceSize;
            // ExceptionTable;
            public UInt32 exceptionRVA;
            public UInt32 exceptionSize;
            // CertificateTable;
            public UInt32 certRVA;
            public UInt32 certSize;
            // BaseRelocationTable;
            public UInt32 base_reloc_RVA;
            public UInt32 base_reloc_Size;
            // Debug;
            public UInt32 debugRVA;
            public UInt32 debugSize;
            //Reserved
            public UInt64 Architecture;
            //GlobalPtr;
            public UInt32 globalptrRVA;
            public UInt32 globalptrSize;
            //TLS_Table;
            public UInt32 tlsRVA;
            public UInt32 tlsSize;
            // LoadConfigTable;
            public UInt32 loadcRVA;
            public UInt32 loadcSize;
            //BoundImport;
            public UInt32 bImportRVA;
            public UInt32 bImportSize;
            // IAT;
            public UInt32 iatRVA;
            public UInt32 iatSize;
            // DelayImportDescriptor;
            public UInt32 dImportRVA;
            public UInt32 dImportSize;
            //NOT SUPPORTED
            public UInt64 CLR_Runtime_Header;
            public UInt64 Reserved;
        }
    }
}
