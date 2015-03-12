/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: Read PE Import Directory tables and IAT
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Windows.Forms;
using Loaders.PEStructures;
using Loaders.Utility;


namespace Loaders.StructReaders.DataSections
{
    class ImportReader : DataSections
    {
        private LinkedList<Import.Import_Directory_Table> import;

        public LinkedList<Import.Import_Directory_Table> Import
        {
            get { return import; }
        }

        private LinkedList<Import.Hint_name_table> importAddrs;

        public LinkedList<Import.Hint_name_table> ImportAddrs
        {
            get { return importAddrs; }
        }

        private LinkedList<Import.Hint_name_table> importNames;

        public LinkedList<Import.Hint_name_table> ImportNames
        {
            get { return importNames; }
        }

        public const int MAX = 1000;
        private UInt64 imageBase = 0x400000;

        public ImportReader(byte[] data, UInt32 size, UInt32 location, UInt32 rvaToOffset,UInt64 imageBase)
            : base(data, size, location, rvaToOffset)
        {
            import = new LinkedList<Import.Import_Directory_Table>();
            importAddrs = new LinkedList<Import.Hint_name_table>();
            this.imageBase = imageBase;
            readDirectory();
        }

        private void readDirectory()
        {
            Import.Import_Directory_Table temp = new Import.Import_Directory_Table();
            LinkedList<Import.Hint_name_table> addrs = new LinkedList<Import.Hint_name_table>();
            LinkedList<Import.Hint_name_table> names = new LinkedList<Import.Hint_name_table>();
            int count = 0;
            while (true)
            {
                temp.id = count;
                temp.rawOffset = (UInt32)(sc.Index+location);
                temp.RVA = temp.rawOffset + rvaToOffset;
                temp.VA = temp.RVA + imageBase;
                temp.OriginalFirstThunk = sc.readFourBytes();
                temp.TimeDateStamp = sc.readFourBytes();
                temp.ForwarderChain = sc.readFourBytes();
                uint name1RVA = sc.readFourBytes();
                uint name1Offset = name1RVA - rvaToOffset;
                Scanner readName = new Scanner((int)name1Offset, data);
                temp.Name1 = Encoding.ASCII.GetString(readNames(readName));
                temp.FirstThunk = sc.readFourBytes();

                if (temp.FirstThunk == 0 && temp.OriginalFirstThunk == 0 && temp.ForwarderChain == 0)
                {
                    break;
                }
                else if (count > MAX)
                {                    
                    throw new InvalidOperationException();
                }
                else
                {
                    temp.ImportNameTableOffset = temp.OriginalFirstThunk - rvaToOffset;
                    temp.ImportAddressTableOffset = temp.FirstThunk - rvaToOffset;
                    import.AddLast(temp);
                    count++;
                }
            }

            for (int i = 0; i < import.Count; i++)
            {
                temp = import.ElementAt(i);
                Import.Hint_name_table nameTemp = new Import.Hint_name_table();
                nameTemp.id = temp.id;
                nameTemp.fileOffset = temp.ImportNameTableOffset;
                names.AddLast(nameTemp);

            }
            importNames = readAddress(names);

            for (int i = 0; i < import.Count; i++)
            {
                temp = import.ElementAt(i);
                Import.Hint_name_table nameTemp = new Import.Hint_name_table();
                nameTemp.id = temp.id;
                nameTemp.fileOffset = temp.ImportAddressTableOffset;
                addrs.AddLast(nameTemp);

            }
            importAddrs = readAddress(addrs);

        }

        private LinkedList<Import.Hint_name_table> readAddress(LinkedList<Import.Hint_name_table> key)
        {
            UInt32 rva = 0;
            LinkedList<Import.Hint_name_table> temp = new LinkedList<Import.Hint_name_table>();
            LinkedList<Import.Hint_name_table> temp2 = new LinkedList<PEStructures.Import.Hint_name_table>();
            Import.Hint_name_table hints;

            for (int i = 0; i < key.Count; i++)
            {
                UInt32 offset = key.ElementAt(i).fileOffset;
                Scanner sc = new Scanner((int)offset, data);
                int count = 0;
                while (true)
                {
                    UInt32 rawOffset = (UInt32)sc.Index;
                    rva = sc.readFourBytes();

                    if (rva <= 0)
                    {
                        break;
                    }
                    else if (count > MAX)
                    {
                        MessageBox.Show(" For optimal performance, we display only the first 1000 entries"); 
                        break;
                    }
                    else if (rva >= 80000000)
                    {
                        hints = new Import.Hint_name_table();
                        hints.id = key.ElementAt(i).id;
                        hints.name = Convert.ToString(rva - 0x80000000);
                        hints.importByName = false;
                        hints.rawOffset = rawOffset;
                        hints.RVA = rawOffset + rvaToOffset;
                        hints.VA = hints.RVA + imageBase;
                        temp.AddLast(hints);
                        count++;
                    }
                    else
                    {

                        hints = new Import.Hint_name_table();
                        hints.importByName = true;
                        hints.id = key.ElementAt(i).id;
                        hints.fileOffset = rva - rvaToOffset;
                        hints.rawOffset = rawOffset;
                        hints.RVA = rawOffset + rvaToOffset;
                        hints.VA = hints.RVA + imageBase;
                        temp.AddLast(hints);
                        count++;
                    }
                }

                if (temp != null)
                {
                    for (int x = 0; x < temp.Count; x++)
                    {

                        LinkedList<byte> functionName = new LinkedList<byte>();
                        hints = temp.ElementAt(x);
                        if (hints.importByName)
                        {
                            sc = new Scanner((int)hints.fileOffset, data);
                            hints.hint = sc.readTwoBytes();
                            byte[] fuc = new byte[1] { 0 };
                            fuc = readNames(sc);

                            try
                            {
                                hints.name = Encoding.ASCII.GetString(fuc);
                            }
                            catch (DecoderFallbackException)
                            {
                                hints.name = "";
                            }
                            temp2.AddLast(hints);
                        }
                        else
                        {
                            hints.name = temp.ElementAt(x).name;
                            hints.hint = 0;
                           temp2.AddLast(hints);
                        }

                    }
                }
            }
            return temp2;
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
                else if (count > MAX)
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