/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: Read PE data sections Header
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
    class DataSectionReader
    {
        private uint noOfSections;
        private uint sectionAlignment;
        private uint entryPoint;
        private SectionHeader.IMAGE_SECTION_TABLE section;
        private LinkedList<SectionHeader.IMAGE_SECTION_TABLE> images;

        public LinkedList<SectionHeader.IMAGE_SECTION_TABLE> Images
        {
            get
            {
                read();
                return images;
            }
        }
        private byte[] data;
        private byte[] dataNeeded;
        private byte[] codeNeeded;
        private byte[] codes;
        
        public DataSectionReader(byte[] rawData, uint entryPoint, uint sectionAlignment, uint noOfSections)
        {
            if (rawData != null && entryPoint > 0 && sectionAlignment > 0)
            {
                this.noOfSections = noOfSections;
                this.sectionAlignment = sectionAlignment;
                this.entryPoint = entryPoint;
                data = rawData;
                dataNeeded = new byte[40 * noOfSections + 40];
                codeNeeded = new byte[sectionAlignment];
                section = new SectionHeader.IMAGE_SECTION_TABLE();
                images = new LinkedList<SectionHeader.IMAGE_SECTION_TABLE>();
                Array.Copy(data, entryPoint, dataNeeded, 0, (int)(40 * noOfSections + 40));

            }
        }

        private void read()
        {
            int index = 0;
            for (int i = 0; i < noOfSections; i++)
            {
                Scanner sc = new Scanner(index, dataNeeded);
                section.Name = sc.readEightBytes();
                string name = new PEReader().readHexToString(section.Name);
                section.VirtualSize = sc.readFourBytes();
                section.VirtualAddress = sc.readFourBytes();
                section.SizeOfRawData = sc.readFourBytes();
                section.PointerToRawData = sc.readFourBytes();
                section.PointerToRelocations = sc.readFourBytes();
                section.PointerToLineNumbers = sc.readFourBytes();
                section.NumberOfRelocations = sc.readTwoBytes();
                section.NumberOfLinenumbers = sc.readTwoBytes();
                section.Characteristics = sc.readFourBytes();
                codes = new byte[section.SizeOfRawData];
                Array.Copy(data, section.PointerToRawData, codes, 0, section.SizeOfRawData);
                index = sc.Index;
                images.AddLast(section);
            }
        }
    }
}
