/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: Read PE DOS Header
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Loaders.Utility;

namespace Loaders.StructReaders
{
    class DOSHeaderReader
    {
        private PEHeader.IMAGE_DOS_HEADER dos;

        public PEHeader.IMAGE_DOS_HEADER Dos
        {
            get
            {
                readHeader();
                return dos;
            }
        }

        private byte[] rawData;
        private byte[] dataNeeded;

        public DOSHeaderReader(byte[] rawData)
        {

            if (rawData != null)
            {
                dos = new PEHeader.IMAGE_DOS_HEADER();
                dataNeeded = new byte[28];
                this.rawData = rawData;
                Array.Copy(rawData, 0, dataNeeded, 0, 28);

            }
        }

        private void readHeader()
        {
            if (dataNeeded != null)
            {
                Scanner sc = new Scanner(0, dataNeeded);
                dos.Identifier = sc.readTwoBytes();

                dos.LastPageSize = sc.readTwoBytes();
                dos.NoOfPages = sc.readTwoBytes();
                dos.RelocationsSize = sc.readTwoBytes();
                dos.HeaderSize = sc.readTwoBytes();
                dos.MinimumExtraPara = sc.readTwoBytes();
                dos.MaximumExtraPara = sc.readTwoBytes();
                dos.InitialSS = sc.readTwoBytes();
                dos.InitialSP = sc.readTwoBytes();
                dos.Checksum = sc.readTwoBytes();
                dos.InitialCS = sc.readTwoBytes();
                dos.InitialIP = sc.readTwoBytes();
                dos.RelocationTable = sc.readTwoBytes();
                dos.OverlayNumber = sc.readTwoBytes();
                dos.getStudSize();


            }
        }

        public bool validate()
        {

            if (dos.Identifier != 0x5a4d)
            {
                MessageBox.Show("This is not an executable");
                throw new ArgumentException();
            }
            else
            {
                return true;
            }

        }
    }
}
