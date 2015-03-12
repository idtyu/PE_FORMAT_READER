/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: Read PE Export Directory table, export name table and export ordinal table
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Loaders.PEStructures;
using Loaders.Utility;
using System.Windows.Forms;


namespace Loaders.StructReaders.DataSections
{
    class ExportReader : DataSections
    {
        private Export.IMAGE_EXPORT_DIRECTORY export;

        public Export.IMAGE_EXPORT_DIRECTORY Export
        {
            get { return export; }
            set { export = value; }
        }
        private Export.Export_Functions[] functions;

        public Export.Export_Functions[] Functions
        {
            get { return functions; }
        }
        private UInt64 imageBase = 0x400000;

        public ExportReader(byte[] data, UInt32 size, UInt32 location, UInt32 rvaToOffset,UInt64 imageBase)
            : base(data, size, location, rvaToOffset)
        {
            export = new Export.IMAGE_EXPORT_DIRECTORY();
            this.imageBase = imageBase;
            readDirectory();
        }

        private void readDirectory()
        {
            Export.IMAGE_EXPORT_DIRECTORY temp = new Export.IMAGE_EXPORT_DIRECTORY(); ;

            //read Directory
            temp.Characteristics = sc.readFourBytes();
            temp.TimeDateStamp = sc.readFourBytes();
            temp.MajorVersion = sc.readTwoBytes();
            temp.MinorVersion = sc.readTwoBytes();
            temp.nName = Encoding.ASCII.GetString(readNames(new Scanner((int)sc.readFourBytes(), data)));            
            temp.nBase = sc.readFourBytes();
            temp.NumberOfFunctions = sc.readFourBytes();
            temp.NumberOfNames = sc.readFourBytes();
            temp.AddressOfFunctions = sc.readFourBytes();
            temp.AddressOfNames = sc.readFourBytes();
            temp.AddressOfNameOrdinals = sc.readFourBytes();
            //read Contents
            if (temp.NumberOfFunctions > 0 && temp.NumberOfNames > 0 && temp.AddressOfFunctions > 0 && temp.AddressOfNameOrdinals > 0 && temp.AddressOfNames > 0)
            {
                //If they are out of range
                if (temp.AddressOfFunctions - rvaToOffset > data.Count() || temp.AddressOfNameOrdinals - rvaToOffset > data.Count() || temp.AddressOfNames - rvaToOffset > data.Count())
                {
                    throw new InvalidOperationException("File offsets error");
                }
                export = temp;
                UInt32[] exportFunctions = new UInt32[export.NumberOfNames];
                UInt16[] exportNameOrdinals = new UInt16[export.NumberOfNames];
                string[] exportNames = new string[export.NumberOfFunctions];
                UInt32[] exportFunctionsOffset = new UInt32[export.NumberOfNames];
                UInt32[] exportNameOrdinalsOffSet = new UInt32[export.NumberOfNames];
                UInt32[] exportNamesOffset = new UInt32[export.NumberOfFunctions];
                LinkedList<Export.Export_Functions> functionList = new LinkedList<Export.Export_Functions>();
                Scanner read = new Scanner((int)(export.AddressOfFunctions - rvaToOffset), data);
                for (int i = 0; i < export.NumberOfNames; i++)
                {
                    exportFunctionsOffset[i] = (UInt32)read.Index;
                    exportFunctions[i] = read.readFourBytes();
                }

                read = new Scanner((int)(export.AddressOfNameOrdinals - rvaToOffset), data);
                for (int i = 0; i < export.NumberOfNames; i++)
                {
                    exportNameOrdinalsOffSet[i] = (UInt32)read.Index;
                    exportNameOrdinals[i] = read.readTwoBytes();
                }
                read = new Scanner((int)(export.AddressOfNames - rvaToOffset), data);
                for (int i = 0; i < export.NumberOfFunctions; i++)
                {
                    Scanner toWords = new Scanner((int)read.readFourBytes(), data);
                    exportNamesOffset[i] = (UInt32)toWords.Index;
                    exportNames[i] = Encoding.ASCII.GetString(readNames(toWords));
                }                
               
                functions = new Export.Export_Functions[export.NumberOfFunctions];
                Export.Export_Functions[] rvasTemp = new Export.Export_Functions[export.NumberOfFunctions];

                for (int x = 0; x < functions.Count(); x++)
                {
                   
                    functions[x].ordinal = exportNameOrdinals[x];
                    functions[x].ordinalRawOffset = exportNameOrdinalsOffSet[x] + location;
                    functions[x].ordinalRVA = functions[x].ordinalRawOffset + rvaToOffset;
                    functions[x].ordinalVA = functions[x].ordinalRVA + imageBase;

                    
                    functions[x].name = exportNames[x];
                    functions[x].nameRawOffset = exportNamesOffset[x];
                    functions[x].nameRVA = functions[x].nameRawOffset + rvaToOffset;
                    functions[x].nameVA = functions[x].nameRVA + imageBase;

                    int ordinal = Convert.ToInt16(functions[x].ordinal);
                    functions[x].RVA = exportFunctions[ordinal];
                    functions[x].RVARawOffset  = exportFunctionsOffset[ordinal];
                    functions[x].RVARVA = exportFunctionsOffset[ordinal]+rvaToOffset ;
                    functions[x].RVAVA = functions[x].RVARVA+imageBase ;  
                }

            }


        }

        private byte[] readNames(Scanner sc)
        {

            int count = 0;
            LinkedList<byte> temp = new LinkedList<byte>();

            while (true)
            {
                Byte newByte = sc.readOneByte();
                if (newByte == 0)
                {
                    break;
                }
                else if (count > ImportReader.MAX)
                {
                    MessageBox.Show(" For optimal performance, we display only the first 1000 entries");
                    break;
                }
                else
                {
                    temp.AddLast(newByte);
                    count++;
                }

            }

            return temp.ToArray();
        }
    }
}
