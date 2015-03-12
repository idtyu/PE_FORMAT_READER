/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: General/super class for data sections
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Loaders.Utility;
using System.Windows.Forms;

namespace Loaders.StructReaders.DataSections
{
    abstract class DataSections
    {
        protected byte[] data;
        protected byte[] dataNeeded;
        protected Scanner sc;
        protected UInt32 size;
        protected UInt32 location;
        protected UInt32 rvaToOffset;

        public DataSections(byte[] data, UInt32 size, UInt32 location, UInt32 rvaToOffset)
        {
            this.data = data;
            this.size = size;
            this.location = location;
            this.rvaToOffset = rvaToOffset;
            if (data != null && size > 0 && location > 0)
            {

                dataNeeded = new byte[size];
                Array.Copy(data, location, dataNeeded, 0, size);
                sc = new Scanner(0, dataNeeded);


            }
        }

        public Dictionary<UInt64, string> sectionTypes = new Dictionary<ulong, string>()
        {
            {0x00000020,"IMAGE_SCN_CNT_CODE"},
            {0x00000040,"IMAGE_SCN_CNT_INITIALIZED_DATA"},
            {0x00000080,"IMAGE_SCN_CNT_UNINITIALIZED_ DATA"},
            {0x01000000,"IMAGE_SCN_LNK_NRELOC_OVFL"}, 
            {0x02000000,"IMAGE_SCN_MEM_DISCARDABLE"},
            {0x04000000,"IMAGE_SCN_MEM_NOT_CACHED"},
            {0x08000000,"IMAGE_SCN_MEM_NOT_PAGED"},
            {0x10000000,"IMAGE_SCN_MEM_SHARED"},
            {0x20000000,"IMAGE_SCN_MEM_EXECUTE"},
            {0x30000000,"IMAGE_SCN_MEM_READ"},
            {0x40000000,"IMAGE_SCN_MEM_WRITE"},
        };      

    }
}
