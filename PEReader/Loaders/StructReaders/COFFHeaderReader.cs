/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: Read PE COFF header
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
    class COFFHeaderReader
    {
        private PEHeader.IMAGE_FILE_HEADER coff;

        public PEHeader.IMAGE_FILE_HEADER Coff
        {
            get
            {
                read();
                return coff;
            }

        }
        public PEHeader.EXTRA_HEADER location;


        private byte[] rawData;
        private byte[] dataNeeded;

        public COFFHeaderReader(byte[] rawData)
        {
            if (rawData != null)
            {
                coff = new PEHeader.IMAGE_FILE_HEADER();
                location = new PEHeader.EXTRA_HEADER();
                dataNeeded = new byte[24];
                this.rawData = rawData;

                int index = 0x3c;
                Scanner sc = new Scanner(index, rawData);
                location.peHeaderLoc = sc.readTwoBytes();
                if (location.peHeaderLoc == 0 || location.peHeaderLoc >= rawData.Count() - 100)
                {
                    throw new InvalidOperationException();
                }
                Array.Copy(rawData, location.peHeaderLoc, dataNeeded, 0, 24);


            }
        }

        private void read()
        {
            if (dataNeeded != null)
            {

                int index = 0;
                Scanner sc = new Scanner(index, dataNeeded);
                coff.peSig = sc.readFourBytes();

                coff.Machine = sc.readTwoBytes();

                coff.NumberOfSections = sc.readTwoBytes();

                coff.TimeDateStamp = sc.readFourBytes();

                coff.PointerToSymbolTable = sc.readFourBytes();

                coff.NumberOfSymbols = sc.readFourBytes();

                coff.SizeOfOptionalHeader = sc.readTwoBytes();

                coff.Characteristics = sc.readTwoBytes();

            }
        }

        public bool validata()
        {
            bool success = false;
            if (coff.peSig == 0x00004550)
            {
                success = true;
            }
            else
            {
                throw new ArgumentException();
            }
            return success;
        }
    }


}
