/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: Compile all PE structure reading togather, and use as an intermediate controller between UI and all other controllers
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Windows.Forms;
using Loaders.StructReaders;
using Loaders.PEStructures;
using Loaders.StructReaders.DataSections;

namespace Loaders
{
    public class PEReader
    {
        private PEHeader.IMAGE_DOS_HEADER dosHeader;

        public PEHeader.IMAGE_DOS_HEADER DosHeader
        {
            get { return dosHeader; }          
        }
        private PEHeader.IMAGE_FILE_HEADER fileHeader;

        public PEHeader.IMAGE_FILE_HEADER FileHeader
        {
            get { return fileHeader; }
        }
        private PEHeader.EXTRA_HEADER extraHeader;

        public PEHeader.EXTRA_HEADER ExtraHeader
        {
            get { return extraHeader; }
        }
        private PEHeader.IMAGE_OPTIONAL_HEADER optionalHeader;

        public PEHeader.IMAGE_OPTIONAL_HEADER OptionalHeader
        {
            get { return optionalHeader; }           
        }
        private PEHeader.IMAGE_DATA_DIRECTORY dataDir;

        public PEHeader.IMAGE_DATA_DIRECTORY DataDir
        {
            get { return dataDir; }
        }
        private LinkedList<SectionHeader.IMAGE_SECTION_TABLE> images;

        public LinkedList<SectionHeader.IMAGE_SECTION_TABLE> Images
        {
            get { return images; }
        }
        private LinkedList<Section.section> dataSections;

        public LinkedList<Section.section> DataSections
        {
            get { return dataSections; }
        }
        private LinkedList<Import.Import_Directory_Table> importDTable;

        public LinkedList<Import.Import_Directory_Table> ImportDTable
        {
            get { return importDTable; }
        }
        private LinkedList<Import.Hint_name_table> iat;

        public LinkedList<Import.Hint_name_table> Iat
        {
            get { return iat; }
        }
        private Export.IMAGE_EXPORT_DIRECTORY export;

        public Export.IMAGE_EXPORT_DIRECTORY Export
        {
            get { return export; }
        }
        private Export.Export_Functions[] exportFunctions;

        public Export.Export_Functions[] ExportFunctions
        {
            get { return exportFunctions; }
        }
        string fileName;
        private byte[] data;

        public byte[] Data
        {
            get { return data; }
        }
        private byte[] codes;

        public byte[] Codes
        {
            get { return codes; }
        }
        private byte[] datas;

        public byte[] Datas
        {
            get { return datas; }
        }
        public bool fileCheck = false;
        public bool optCheck = false;
        public bool dosCheck = false;
        public bool hasImport = false;
        public bool hasExport = false;
        public bool hasCode = false;
        public bool hasData = false;
        public bool indivisualCodeSection = true;

        public PEReader(String filePath)
        {
            fileName = filePath;
            try
            {
                data = File.ReadAllBytes(fileName);
            }
            catch
            {
                MessageBox.Show("Uh Oh!");
                return;
            }

            dosHeader = new PEHeader.IMAGE_DOS_HEADER();
            dataSections = new LinkedList<Section.section>();
            try
            {
                readDOSHeader();
            }
            catch (RankException)
            {
                //for catching all supported errors
            }
            catch (OutOfMemoryException)
            {
                MessageBox.Show("You do not have sufficient memory", "ERROR_MEMORY");
            }
            catch (ArgumentNullException)
            {
                MessageBox.Show("Internal Program eror");

            }
            catch (InvalidOperationException)
            {
                //#FileAltered
                MessageBox.Show("This program may be corrupted or edited, please obtain another copy of this software.");

            }
            catch (ArgumentOutOfRangeException)
            {
                MessageBox.Show("The file is corrupted");

            }
            catch (ArgumentException)
            {
                MessageBox.Show("The file is corrupted or in an incorrect format");

            }
            catch (Exception e)
            {
                MessageBox.Show("Software error : " + e.ToString());

            }
        }

        public PEReader() { }

        public string readHexToString(UInt64 toConvert)
        {
            string hex = "";
            try
            {
                hex = Encoding.ASCII.GetString(BitConverter.GetBytes(toConvert)).Replace("-", " ");
            }
            catch (ArgumentNullException ane)
            {
                throw ane;
            }
            catch (ArgumentException ar)
            {
                throw ar;
            }

            return hex;
        }

        public string readHexAddress(UInt64 toConvert)
        {
            string hex = "";
            try
            {
                hex = "0x" + toConvert.ToString("X8");
            }
            catch (NullReferenceException)
            {
                throw new ArgumentNullException();
            }
            return hex;
        }

        // reverse byte order (16-bit)
        public static UInt16 ReverseBytes(UInt16 value)
        {
            try
            {
                return (UInt16)((value & 0xFFU) << 8 | (value & 0xFF00U) >> 8);
            }
            catch (ArgumentNullException a)
            {
                throw a;
            }
            catch (InvalidOperationException)
            {
                throw new ArgumentException();
            }
            catch (ArgumentException e)
            {
                throw e;
            }
        }


        // reverse byte order (32-bit)
        public static UInt32 ReverseBytes(UInt32 value)
        {
            try
            {
                return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
                       (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
            }
            catch (ArgumentNullException a)
            {
                throw a;
            }
            catch (InvalidOperationException)
            {
                throw new ArgumentException();
            }
            catch (ArgumentException e)
            {
                throw e;
            }
        }


        // reverse byte order (64-bit)
        public static UInt64 ReverseBytes(UInt64 value)
        {
            try
            {
                return (value & 0x00000000000000FFUL) << 56 | (value & 0x000000000000FF00UL) << 40 |
                       (value & 0x0000000000FF0000UL) << 24 | (value & 0x00000000FF000000UL) << 8 |
                       (value & 0x000000FF00000000UL) >> 8 | (value & 0x0000FF0000000000UL) >> 24 |
                       (value & 0x00FF000000000000UL) >> 40 | (value & 0xFF00000000000000UL) >> 56;
            }
            catch (ArgumentNullException a)
            {
                throw a;
            }
            catch (InvalidOperationException)
            {
                throw new ArgumentException();
            }
            catch (ArgumentException e)
            {
                throw e;
            }
        }

        private void readDOSHeader()
        {

            DOSHeaderReader read = new DOSHeaderReader(data);
            dosHeader = read.Dos;
            dosCheck = read.validate();
            if (dosCheck == true)
            {
                readFileHeader();
            }

        }

        private void readFileHeader()
        {
            COFFHeaderReader coff = new COFFHeaderReader(data);
            fileHeader = coff.Coff;
            extraHeader = coff.location;
            fileCheck = coff.validata();
            if (fileCheck == true)
            {
                readOptionalHeader();
            }
        }

        private void readOptionalHeader()
        {
            OptionalHeaderReader opt = new OptionalHeaderReader(data, extraHeader.peHeaderLoc + 24);
            optionalHeader = opt.OpHead;
            optCheck = opt.validate();
            if (optCheck == true)
            {
                readDataDirectory();
            }

        }

        private void readDataDirectory()
        {
            int x = 96;
            if (optionalHeader.Magic == 0x010b)
            {
                x = 120;
            }
            else
            {
                x = 136;
            }
            DataDirectoryReader dir = new DataDirectoryReader(extraHeader.peHeaderLoc + x, data);
            this.dataDir = dir.DataDir;
            x = extraHeader.peHeaderLoc + x + 16 * 8;
            DataSectionReader ds = new DataSectionReader(data, (uint)x, optionalHeader.SectionAlignment, fileHeader.NumberOfSections);
            this.images = ds.Images;
            if (images.Count > 0)
            {
                for (int n = 0; n < images.Count; n++)
                {
                    UInt32 start = images.ElementAt(n).VirtualAddress;
                    UInt32 end = images.ElementAt(n).VirtualSize + images.ElementAt(n).VirtualAddress;
                    UInt32 toOffset = PEReader.toFileOffset(start, images.ElementAt(n).PointerToRawData);
                    
                    Section.section sec = new Section.section();
                    sec.rvaToOffset = toOffset;
                    sec.header = images.ElementAt(n);
                    if (dataDir.importRVA >= start && dataDir.importRVA < end)
                    {
                        sec.import = dataDir.importRVA - toOffset;
                    } if (dataDir.exportRVA >= start && dataDir.exportRVA < end)
                    {
                        sec.export = dataDir.exportRVA - toOffset;
                    }
                    dataSections.AddLast(sec);
                }

            }
            if (dataSections != null)
            {
                determineSections();
            }
        }

        //putting functions into different sections is for furthur development on GUI
        private void determineSections()
        {

            for (int i = 0; i < images.Count; i++)
            {
                //As there are not structure but raw data in both .text and .data section, there will only no seperate class for them
                SectionHeader.IMAGE_SECTION_TABLE temp = images.ElementAt(i);
                if (new PEReader().readHexToString(temp.Name).Contains(".text") || new PEReader().readHexToString(temp.Name).Contains("code"))
                {
                    readCodes(temp.SizeOfRawData, temp.PointerToRawData);
                    hasCode = true;
                }
                else
                {
                    indivisualCodeSection = false;
                }
                if (new PEReader().readHexToString(temp.Name).Contains(".data"))
                {
                    readDatas(temp.SizeOfRawData, temp.PointerToRawData);
                    hasData = true;
                }
                else
                {
                    Section.section section = new Section.section();
                    section = dataSections.ElementAt(i);
                    UInt32 offset = PEReader.toFileOffset(section.header.VirtualAddress, section.header.PointerToRawData);
                    if (section.import > 0)
                    {
                        ImportReader ir = new ImportReader(data, 500, (UInt32)section.import, offset,optionalHeader.ImageBase );
                        section.importAddr = ir.ImportAddrs;
                        section.importDirTable = ir.Import;
                        importDTable = ir.Import;
                        iat = ir.ImportAddrs;
                        hasImport = true;
                    } if (section.export > 0)
                    {
                        ExportReader er = new ExportReader(data, 500, (UInt32)section.export, offset,optionalHeader.ImageBase );
                        section.exportDirectory = er.Export;
                        export = er.Export;
                        section.functions = er.Functions;
                        exportFunctions = er.Functions;
                        hasExport = true;
                    } if (indivisualCodeSection == false)
                    {
                    }
                }
            }
        }

        private void readCodes(UInt32 size, UInt32 location)
        {

            codes = new byte[size];
            Array.Copy(data, (int)location, codes, 0, (int)size);
        }

        private void readDatas(UInt32 size, UInt32 location)
        {

            datas = new byte[size];
            Array.Copy(data, (int)location, datas, 0, (int)size);
        }

        public static UInt32 toFileOffset(UInt32 rva, UInt32 rawAddress)
        {
            UInt32 offset = rva - rawAddress;
            return offset;
        }
    }
}
