/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: Read PE Data Directory
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Loaders.StructReaders;
using Loaders.Utility;

namespace Loaders.StructReaders
{
    class DataDirectoryReader
    {
        private PEHeader.IMAGE_DATA_DIRECTORY dataDir;

        public PEHeader.IMAGE_DATA_DIRECTORY DataDir
        {
            get
            {
                read();
                return dataDir;
            }
            set { dataDir = value; }
        }
        private byte[] data;
        private byte[] dataNeeded;

        public DataDirectoryReader(int index, byte[] data)
        {
            this.data = data;
            if (data != null)
            {
                dataNeeded = new byte[128];
                dataDir = new PEHeader.IMAGE_DATA_DIRECTORY();

                Array.Copy(data, index, dataNeeded, 0, 128);

            }
        }

        private void read()
        {
            if (dataNeeded != null)
            {
                Scanner sc = new Scanner(0, dataNeeded);
               
                dataDir.exportRVA = sc.readFourBytes();
                dataDir.exportSize = sc.readFourBytes();
                
                dataDir.importRVA = sc.readFourBytes();
                dataDir.importSize = sc.readFourBytes();
               
                dataDir.resourceRVA = sc.readFourBytes();
                dataDir.resourceSize = sc.readFourBytes();
               
                dataDir.exceptionRVA = sc.readFourBytes();
                dataDir.exceptionSize = sc.readFourBytes();
              
                dataDir.certRVA = sc.readFourBytes();
                dataDir.certSize = sc.readFourBytes();
             
                dataDir.base_reloc_RVA = sc.readFourBytes();
                dataDir.base_reloc_Size = sc.readFourBytes();
              
                dataDir.debugRVA = sc.readFourBytes();
                dataDir.debugSize = sc.readFourBytes();
                //Reserved
                dataDir.Architecture = sc.readEightBytes();
                
                dataDir.globalptrRVA = sc.readFourBytes();
                dataDir.globalptrSize = sc.readFourBytes();
                
                dataDir.tlsRVA = sc.readFourBytes();
                dataDir.tlsSize = sc.readFourBytes();
                
                dataDir.loadcRVA = sc.readFourBytes();
                dataDir.loadcSize = sc.readFourBytes();
                
                dataDir.bImportRVA = sc.readFourBytes();
                dataDir.bImportSize = sc.readFourBytes();
                
                dataDir.iatRVA = sc.readFourBytes();
                dataDir.iatSize = sc.readFourBytes();
               
                dataDir.dImportRVA = sc.readFourBytes();
                dataDir.dImportSize = sc.readFourBytes();
                dataDir.CLR_Runtime_Header = sc.readEightBytes();
                dataDir.Reserved = sc.readEightBytes();
                
            }
        }        
    }
}
