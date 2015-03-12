/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: Read PE Optional header also know at winnt.h
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Loaders.Utility;


namespace Loaders.StructReaders
{
    class OptionalHeaderReader
    {
        private PEHeader.IMAGE_OPTIONAL_HEADER opHead;

        public PEHeader.IMAGE_OPTIONAL_HEADER OpHead
        {
            get
            {
                if (if32bit())
                {
                    read();
                }
                else
                {
                    //read64bit();
                    MessageBox.Show(" We are sorry, but we do not support 64 bit PE at this moment");
                    throw new RankException();
                }
                return opHead;
            }

        }
        private byte[] rawData;
        private byte[] dataNeeded;



        public OptionalHeaderReader(byte[] rawData, int location)
        {
            if (rawData != null)
            {
                opHead = new PEHeader.IMAGE_OPTIONAL_HEADER();
                Scanner sc = new Scanner(location, rawData);
                opHead.Magic = sc.readTwoBytes();

                this.rawData = rawData;

                if (if32bit())
                {
                    dataNeeded = new byte[96];
                    Array.Copy(rawData, location + 2, dataNeeded, 0, 96);
                }
                else
                {
                    MessageBox.Show("Sorry, 64 bit is not supported");
                    throw new RankException();
                }

            }
        }

        public bool if32bit()
        {
            if (opHead.Magic == 0x010b)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private void read()
        {
            if (dataNeeded != null)
            {

                Scanner sc = new Scanner(0, dataNeeded);

                opHead.MajorLinkerVersion = sc.readOneByte();

                string str = opHead.MajorLinkerVersion.ToString("X2");

                char[] digits = str.ToCharArray();

                opHead.MinorLinkerVersion = (byte)"0123456789ABCDEF".IndexOf(char.ToUpper(str[0]));
                opHead.MajorLinkerVersion = (byte)"0123456789ABCDEF".IndexOf(char.ToUpper(str[1]));

                opHead.SizeOfCode = PEReader.ReverseBytes(sc.readFourBytes());

                opHead.SizeOfInitializedData = PEReader.ReverseBytes(sc.readFourBytes());

                opHead.SizeOfUninitializedData = PEReader.ReverseBytes(sc.readFourBytes());

                sc.Index += 1;
                opHead.AddressOfEntryPoint = sc.readFourBytes();

                opHead.BaseOfCode = sc.readFourBytes();


                opHead.BaseOfData = sc.readFourBytes();

                opHead.ImageBase = sc.readFourBytes();
                // sc.index -= 1;

                if (opHead.ImageBase > 0)
                {
                    opHead.code_va = opHead.ImageBase + opHead.BaseOfCode;
                    if (opHead.BaseOfData > 0)
                    {
                        opHead.data_va = opHead.BaseOfData + opHead.ImageBase;
                    }
                    opHead.entryPtr_va = opHead.AddressOfEntryPoint + opHead.ImageBase;
                }
                opHead.SectionAlignment = PEReader.ReverseBytes(sc.readFourBytes());

                opHead.FileAlignment = PEReader.ReverseBytes(sc.readFourBytes());

                opHead.MajorOperatingSystemVersion = sc.readTwoBytes();

                opHead.MinorOperatingSystemVersion = sc.readTwoBytes();

                opHead.MajorImageVersion = sc.readTwoBytes();

                opHead.MinorImageVersion = sc.readTwoBytes();

                opHead.MajorSubSystemVersion = sc.readTwoBytes();

                opHead.MinorSubSystemVersion = sc.readTwoBytes();

                opHead.Win32VersionValue = sc.readFourBytes();

                opHead.SizeOfImage = sc.readFourBytes();

                opHead.SizeOfHeaders = sc.readFourBytes();

                opHead.CheckSum = sc.readFourBytes();

                opHead.Subsystem = sc.readTwoBytes();

                opHead.DllCharacteristics =sc.readTwoBytes();

                opHead.SizeOfStackReserve = sc.readFourBytes();

                opHead.SizeOfStackCommit = sc.readFourBytes();

                opHead.SizeOfHeapReserve = sc.readFourBytes();

                opHead.SizeOfHeapCommit = sc.readFourBytes();

                opHead.LoaderFlags = sc.readFourBytes();

                opHead.NumberOfRvaAndSizes = sc.readFourBytes();

            }
        }
        //Can work, but no longer supported
        private void read64bit()
        {
            if (!if32bit() && dataNeeded != null)
            {

                Scanner sc = new Scanner(0, dataNeeded);

                opHead.MajorLinkerVersion = sc.readOneByte();

                string str = opHead.MajorLinkerVersion.ToString("X2");

                char[] digits = str.ToCharArray();

                opHead.MinorLinkerVersion = (byte)"0123456789ABCDEF".IndexOf(char.ToUpper(str[0]));
                opHead.MajorLinkerVersion = (byte)"0123456789ABCDEF".IndexOf(char.ToUpper(str[1]));

                opHead.SizeOfCode = sc.readFourBytes();

                opHead.SizeOfInitializedData = sc.readFourBytes();

                opHead.SizeOfUninitializedData = sc.readFourBytes();

                opHead.AddressOfEntryPoint = sc.readFourBytes();

                opHead.BaseOfCode = sc.readFourBytes();

                sc.Index += 1;
                opHead.ImageBase = sc.readEightBytes();


                if (opHead.ImageBase > 0)
                {
                    opHead.code_va = opHead.ImageBase + opHead.BaseOfCode;

                    opHead.entryPtr_va = opHead.AddressOfEntryPoint + opHead.ImageBase;
                }
                opHead.SectionAlignment = sc.readFourBytes();

                opHead.FileAlignment = sc.readFourBytes();

                opHead.MajorOperatingSystemVersion = sc.readTwoBytes();

                opHead.MinorOperatingSystemVersion = sc.readTwoBytes();

                opHead.MajorImageVersion = sc.readTwoBytes();

                opHead.MinorImageVersion = sc.readTwoBytes();

                opHead.MajorSubSystemVersion = sc.readTwoBytes();

                opHead.MinorSubSystemVersion = sc.readTwoBytes();

                opHead.Win32VersionValue = sc.readFourBytes();

                opHead.SizeOfImage = sc.readFourBytes();

                opHead.SizeOfHeaders = sc.readFourBytes();

                opHead.CheckSum = sc.readFourBytes();

                opHead.Subsystem = sc.readTwoBytes();

                opHead.DllCharacteristics = sc.readTwoBytes();

                opHead.SizeOfStackReserve = sc.readEightBytes();

                opHead.SizeOfStackCommit = sc.readEightBytes();

                opHead.SizeOfHeapReserve = sc.readEightBytes();

                opHead.SizeOfHeapCommit = sc.readEightBytes();

                opHead.LoaderFlags = sc.readFourBytes();

                opHead.NumberOfRvaAndSizes = sc.readFourBytes();

            }
        }

        public bool validate()
        {
            bool success = false;
            if (!(opHead.Magic == 0x020b || opHead.Magic == 0x010b))
            {
                MessageBox.Show(" We can only read PE32 and PE32+ files");
                throw new RankException();
            }
            else if (opHead.ImageBase <= 0)
            {
                MessageBox.Show(" The base of image is 0, file format error");
                throw new RankException();
            }

            else
            {
                success = true;
            }
            return success;
        }
    }
}
