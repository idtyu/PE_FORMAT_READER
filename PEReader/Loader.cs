/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: User Interface class and displaying data
*/
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Threading;
using System.IO;
using Loaders;
using Loaders.PEStructures;
using Binalysis.Interpreters.Intel;
using Binalysis.Translators;
using Binalysis.Translators.Intel;
using Binalysis.Reporters;


namespace Binalysis
{
    public partial class Loader : Form
    {

        private PEReader pe;

        public Loader()
        {
            InitializeComponent();
        }

        private void openToolStripMenuItem_Click(object sender, EventArgs e)
        {
            
            try
            {
                Reset();
                setLabels();               
                
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
                return;
            }
            catch (InvalidOperationException)
            {
                //#FileAltered
                MessageBox.Show("This program may be corrupted or edited, please obtain another copy of this software.");
                return;
            }
            catch (ArgumentOutOfRangeException)
            {
                MessageBox.Show("The file is corrupted");
                return;
            }
            catch (ArgumentException)
            {
                MessageBox.Show("The file is corrupted or in an incorrect format");
                return;
            }
            catch (Exception err)
            {
                
                if (err.Message.ToUpper().Equals("OPCODE UNRECOGNIZED"))
                {
                    MessageBox.Show("Part of the code is not supported.");
                    disassemblyDump.Text = "Part of the code is not supported.";
                    analysisResult.Text = "Part of the code is not supported.";
                }
                else
                {
                    MessageBox.Show("Software error : " + err.ToString());
                }
                return;
            }
        }

        private void Exit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        public void setLabels()
        {
            try
            {
                DialogResult result = openFileDialog1.ShowDialog();
                if (result == DialogResult.OK)
                {
                    
                    string fileName = openFileDialog1.FileName;                   
                    pe = new PEReader(fileName);
                    
                    string final = BitConverter.ToString(pe.Data).Replace("-", " ");
                    richTextBox1.Text = final;
                    openFileDialog1.Dispose();
                    label3.Text = pe.readHexToString(pe.DosHeader.Identifier);


                    if (pe.DosHeader.Identifier == 0x5a4d && pe.dosCheck == true)
                    {
                        Main.Visible = true;

                        label5.Text = Convert.ToString(pe.DosHeader.LastPageSize);

                        label7.Text = Convert.ToString(pe.DosHeader.NoOfPages);

                        label9.Text = Convert.ToString(pe.DosHeader.RelocationsSize);

                        label11.Text = Convert.ToString(pe.DosHeader.HeaderSize);

                        label14.Text = Convert.ToString(pe.DosHeader.MinimumExtraPara);

                        label15.Text = Convert.ToString(pe.DosHeader.MaximumExtraPara);

                        label18.Text = Convert.ToString(pe.DosHeader.InitialSS);

                        label19.Text = Convert.ToString(pe.DosHeader.InitialSP);

                        label23.Text = Convert.ToString(pe.DosHeader.Checksum);

                        label24.Text = Convert.ToString(pe.DosHeader.InitialCS);

                        label27.Text = Convert.ToString(pe.DosHeader.InitialIP);

                        label28.Text = pe.readHexAddress(pe.DosHeader.RelocationTable);

                        label29.Text = Convert.ToString(pe.DosHeader.OverlayNumber);

                        label32.Text = Convert.ToString(pe.DosHeader.studSize);

                        label35.Text = pe.readHexAddress(pe.ExtraHeader.peHeaderLoc);

                        //Set PE/Coff Header

                        label33.Text = pe.readHexToString(pe.FileHeader.peSig);

                        //find machine time

                        Dictionary<UInt32, string> x = PEHeader.machineType;

                        try
                        {
                            string machine = x[pe.FileHeader.Machine];
                            label37.Text = machine;
                        }
                        catch
                        {
                            label37.Text = "Not available, DLL file";
                        }

                        if (pe.fileCheck == true)
                        {
                            label39.Text = Convert.ToString(pe.FileHeader.NumberOfSections);


                            label41.Text = getTime(pe.FileHeader.TimeDateStamp);

                            label43.Text = pe.readHexAddress(pe.FileHeader.PointerToSymbolTable);

                            label47.Text = Convert.ToString(pe.FileHeader.NumberOfSymbols);

                            label48.Text = Convert.ToString(pe.FileHeader.SizeOfOptionalHeader);

                            //read characteristics
                            string hexed = BitConverter.ToString(BitConverter.GetBytes(pe.FileHeader.Characteristics)).Replace("-", " ");
                            label49.Text = "0x" + hexed;
                            char[] conv = hexed.Replace(" ", string.Empty).ToCharArray();
                            string charflags = "";

                            try
                            {
                                charflags += PEHeader.charFlag2[(UInt16)char.GetNumericValue(conv[0])] + " ,";
                            }
                            catch (Exception) { }
                            try
                            {
                                charflags += PEHeader.charFlag3[(UInt16)char.GetNumericValue(conv[1])] + " ,";
                            }
                            catch (Exception) { }
                            try
                            {
                                charflags += PEHeader.charFlag0[(UInt16)char.GetNumericValue(conv[2])] + " ,";
                            }
                            catch (Exception) { }
                            try
                            {
                                charflags += PEHeader.charFlag1[(UInt16)char.GetNumericValue(conv[3])];
                            }
                            catch (Exception) { }

                            label49.Text += "," + charflags;

                            if (pe.optCheck == true)
                            {
                                label59.Text = PEHeader.magic[pe.OptionalHeader.Magic];

                                label60.Text = Convert.ToString(pe.OptionalHeader.MajorLinkerVersion + "." + pe.OptionalHeader.MinorLinkerVersion);

                                label62.Text = Convert.ToString(pe.OptionalHeader.SizeOfCode);

                                label63.Text = Convert.ToString(pe.OptionalHeader.SizeOfInitializedData);

                                label64.Text = Convert.ToString(pe.OptionalHeader.SizeOfUninitializedData);

                                label65.Text = pe.readHexAddress(pe.OptionalHeader.AddressOfEntryPoint);

                                label66.Text = pe.readHexAddress(pe.OptionalHeader.BaseOfCode);

                                label67.Text = pe.readHexAddress(pe.OptionalHeader.BaseOfData);

                                label70.Text = pe.readHexAddress(pe.OptionalHeader.ImageBase);

                                label71.Text = pe.readHexAddress(pe.OptionalHeader.SectionAlignment);

                                label72.Text = pe.readHexAddress(pe.OptionalHeader.FileAlignment);

                                label73.Text = pe.readHexAddress(pe.OptionalHeader.code_va);

                                label76.Text = pe.readHexAddress(pe.OptionalHeader.data_va);

                                label77.Text = pe.readHexAddress(pe.OptionalHeader.entryPtr_va);

                                label79.Text = Convert.ToString(pe.OptionalHeader.MajorOperatingSystemVersion) + "." + Convert.ToString(pe.OptionalHeader.MinorOperatingSystemVersion);
                                try
                                {
                                    label79.Text = label79.Text + "," + PEHeader.winVersion[label79.Text];
                                }
                                catch (Exception)
                                {
                                }

                                label81.Text = Convert.ToString(pe.OptionalHeader.MajorImageVersion) + "." + Convert.ToString(pe.OptionalHeader.MinorImageVersion);

                                label83.Text = Convert.ToString(pe.OptionalHeader.MajorSubSystemVersion) + "." + Convert.ToString(pe.OptionalHeader.MinorSubSystemVersion);
                                try
                                {
                                    label83.Text = label83.Text + "," + PEHeader.winVersion[label83.Text];
                                }
                                catch (Exception)
                                {
                                }
                                label87.Text = Convert.ToString(pe.OptionalHeader.SizeOfImage);

                                label89.Text = Convert.ToString(pe.OptionalHeader.SizeOfHeaders);

                                label91.Text = Convert.ToString(pe.OptionalHeader.CheckSum);

                                try
                                {
                                    byte[] invert = BitConverter.GetBytes(pe.OptionalHeader.Subsystem);
                                    label93.Text = PEHeader.subsystem[(UInt16)(BitConverter.ToInt16(invert, 0))];
                                }
                                catch (Exception) { }

                                char[] temp =pe.OptionalHeader.DllCharacteristics.ToString("X4").ToCharArray();
                                //Array.Reverse(temp);
                                UInt16 ks = (UInt16)(char.GetNumericValue(temp[0]) * 1000);
                                UInt16 hundres = (UInt16)((int)char.GetNumericValue(temp[1]) * 100);
                                UInt16 tens = (UInt16)(char.GetNumericValue(temp[2]) * 10);
                                UInt16 ones = (UInt16)(char.GetNumericValue(temp[3]));

                                try
                                {
                                    label95.Text = pe.readHexAddress(pe.OptionalHeader.DllCharacteristics);
                                    label95.Text += "," + PEHeader.dllChar[ks] + ",";
                                    label95.Text += PEHeader.dllChar[hundres] + ",";
                                    label95.Text += PEHeader.dllChar[tens] + ",";
                                    label95.Text += PEHeader.dllChar[ones];
                                }
                                catch (Exception) { }
                                label97.Text = Convert.ToString((double)(pe.OptionalHeader.SizeOfStackReserve / 8 / 1024) ) + " KB";

                                label99.Text = Convert.ToString((double)(pe.OptionalHeader.SizeOfStackCommit / 8)) + " Bits";

                                label101.Text = Convert.ToString((double)(pe.OptionalHeader.SizeOfHeapReserve / 8)) + " Bits";

                                label103.Text = Convert.ToString((double)(pe.OptionalHeader.SizeOfHeapCommit / 8)) + " Bits";

                                label107.Text = Convert.ToString((double)(pe.OptionalHeader.NumberOfRvaAndSizes / 8)) + " Bits";

                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.exportRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.importRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.resourceRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.exceptionRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.certRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.base_reloc_RVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.debugRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add("Reserved");
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.globalptrRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.tlsRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.loadcRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.bImportRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.iatRVA));
                                listBox2.Items.Add("");
                                listBox2.Items.Add(pe.readHexAddress(pe.DataDir.dImportRVA));
                                listBox2.Items.Add("");


                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.exportSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.importSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.resourceSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.exceptionSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.certSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.base_reloc_Size));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.debugSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add("Reserved");
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.globalptrSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.tlsSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.loadcSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.bImportSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.iatSize));
                                listBox3.Items.Add("");
                                listBox3.Items.Add(pe.readHexAddress(pe.DataDir.dImportSize));
                                listBox3.Items.Add("");
                                loadToView1();
                               
                                if (pe.hasData)
                                {
                                    richTextBox2.Text = BitConverter.ToString(pe.Datas).Replace('-', ' ');

                                }
                                if (pe.hasImport)
                                {
                                    loadToImports();

                                }
                                if (pe.hasExport)
                                {
                                    loadToExport();
                                }

                                if (pe.hasCode)
                                {
                                    code.Text = BitConverter.ToString(pe.Codes).Replace('-', ' ');
                                    System.IO.FileInfo fInfo = new System.IO.FileInfo(openFileDialog1.FileName);
                                    if (fInfo.Extension == ".dll" || fInfo.Extension == ".DLL")
                                    {
                                        disassemblyDump.Text = "DLL function not supported.";
                                        analysisResult.Text = "DLL function not supported.";
                                    }
                                    else
                                    {
                                        X86IntelTranslator x86Translator = new X86IntelTranslator(pe.Codes);
                                        disassemblyDump.Text = x86Translator.GetStringIntelAssemblyInstructions();
                                        X86IntelInterpreter x86Interpretor =
                                            new X86IntelInterpreter(x86Translator.GetIntelAssemblyInstructions(), pe);
                                        Reporter reporter = new Reporter(x86Interpretor.GetAnalysisResults());
                                        analysisResult.Text = reporter.GenerateReport();
                                    }
                                }
                            }
                        }

                    }

                }
                else
                {
                    MessageBox.Show("File not opened successfully");
                    throw new RankException();

                }
            }
            catch (ArgumentOutOfRangeException ao)
            {               
                throw ao;
            }
            catch (ArgumentException ae)
            {
                throw ae;
            }
            catch (Exception e)
            {
                throw e;
            }
        }


        private void closeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            openFileDialog1.Dispose();
        }

        private void loadToView1()
        {
            LinkedList<SectionHeader.IMAGE_SECTION_TABLE> images = pe.Images;

            dataGridView1.Rows.Add(images.Count);
            for (int i = 0; i < images.Count; i++)
            {

                dataGridView1[0, i].Value = pe.readHexToString(images.ElementAt(i).Name);
                dataGridView1[1, i].Value = pe.readHexAddress(images.ElementAt(i).VirtualSize);
                dataGridView1[2, i].Value = pe.readHexAddress(images.ElementAt(i).VirtualAddress);
                dataGridView1[3, i].Value = Convert.ToString(images.ElementAt(i).SizeOfRawData);
                dataGridView1[4, i].Value = pe.readHexAddress(images.ElementAt(i).PointerToRawData);
                dataGridView1[5, i].Value = pe.readHexAddress(images.ElementAt(i).PointerToRelocations);
                dataGridView1[6, i].Value = pe.readHexAddress(images.ElementAt(i).PointerToLineNumbers);
                dataGridView1[7, i].Value = Convert.ToString(images.ElementAt(i).NumberOfRelocations);
                dataGridView1[8, i].Value = pe.readHexAddress(images.ElementAt(i).PointerToLineNumbers);
                dataGridView1[9, i].Value = pe.readHexAddress(images.ElementAt(i).Characteristics);
              
            }
        }

        private void loadToImports()
        {

          
            ImportDTable.Rows.Clear();
            IAT.Rows.Clear();
            LinkedList<Import.Import_Directory_Table> importDir = pe.ImportDTable;
            LinkedList<Import.Hint_name_table> iat = pe.Iat;
            ImportDTable.Rows.Add(importDir.Count);
            IAT.Rows.Add(iat.Count);
            int i = 0;
            for (i = 0; i < importDir.Count; i++)
            {
                Import.Import_Directory_Table temp = importDir.ElementAt(i);
                ImportDTable[0, i].Value = pe.readHexAddress(temp.OriginalFirstThunk);
                ImportDTable[1, i].Value = Convert.ToString(temp.TimeDateStamp);
                ImportDTable[2, i].Value = pe.readHexAddress(temp.ForwarderChain);
                ImportDTable[3, i].Value = temp.Name1;
                ImportDTable[4, i].Value = pe.readHexAddress(temp.FirstThunk);
                ImportDTable[5, i].Value = pe.readHexAddress (importDir.ElementAt(i).rawOffset);
                ImportDTable[6, i].Value = pe.readHexAddress(importDir.ElementAt(i).RVA);
                ImportDTable[7, i].Value = pe.readHexAddress(importDir.ElementAt(i).VA);
            }

            for (i = 0; i < iat.Count; i++)
            {
                Import.Hint_name_table tmp = iat.ElementAt(i);
                IAT[0, i].Value = importDir.ElementAt(tmp.id).Name1;
                IAT[1, i].Value = pe.readHexAddress(tmp.hint);
                IAT[2, i].Value = tmp.name;
                IAT[3, i].Value = pe.readHexAddress (tmp.rawOffset);
                IAT[4, i].Value = pe.readHexAddress(tmp.RVA);
                IAT[5, i].Value = pe.readHexAddress(tmp.VA);
            }
        }

        private void loadToExport()
        {
          
            ExportTable.Rows.Clear();
            ExportTable.Rows.Add(pe.ExportFunctions.Count());
            Export.IMAGE_EXPORT_DIRECTORY tmp = pe.Export;
            label112.Text = Convert.ToString(tmp.Characteristics);
            UInt32 x = tmp.TimeDateStamp;
            if (x > 0)
            {
                label114.Text = getTime(x);
            }
            else
            {
                label114.Text = "0";
            }
            label116.Text = Convert.ToString(tmp.MajorVersion);
            label118.Text = Convert.ToString(tmp.MinorVersion);
            label127.Text = tmp.nName;
            label128.Text = Convert.ToString(tmp.nBase);
            label129.Text = Convert.ToString(tmp.NumberOfFunctions);
            label130.Text = Convert.ToString(tmp.NumberOfNames);
            label131.Text = pe.readHexAddress(tmp.AddressOfFunctions);
            label132.Text = pe.readHexAddress(tmp.AddressOfNameOrdinals);
            label133.Text = pe.readHexAddress(tmp.AddressOfNames);
            for (int i = 0; i < pe.ExportFunctions.Count(); i++)
            {
                ExportTable[0, i].Value = Convert.ToString(pe.ExportFunctions[i].ordinal);
                ExportTable[1, i].Value = pe.ExportFunctions[i].name;
                ExportTable[2, i].Value = pe.readHexAddress(pe.ExportFunctions[i].RVA);
                //ordinal
                ExportTable[3, i].Value = pe.readHexAddress(pe.ExportFunctions[i].ordinalRawOffset ) ;
                ExportTable[4, i].Value = pe.readHexAddress(pe.ExportFunctions[i].ordinalRVA);
                ExportTable[5, i].Value = pe.readHexAddress(pe.ExportFunctions[i].ordinalVA); ;
                //name
                ExportTable[6, i].Value = pe.readHexAddress(pe.ExportFunctions[i].nameRawOffset);
                ExportTable[7, i].Value = pe.readHexAddress(pe.ExportFunctions[i].nameRVA);
                ExportTable[8, i].Value = pe.readHexAddress(pe.ExportFunctions[i].nameVA); ;
                //pointer
                ExportTable[9, i].Value = pe.readHexAddress(pe.ExportFunctions[i].RVARawOffset);
                ExportTable[10, i].Value = pe.readHexAddress(pe.ExportFunctions[i].RVARVA);
                ExportTable[11, i].Value = pe.readHexAddress(pe.ExportFunctions[i].RVAVA); ;
            }
        }

        //Microsoft PE format starts from 1/1/1970
        private string getTime(uint seconds)
        {
            DateTime original = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            original = original.AddSeconds(seconds);
            return original.ToString();
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Form about = new Binalysis.Loaders.AboutBox1();
            about.Show();
        }

       

        private void helpToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(Application.StartupPath + "\\Help.chm");
            }
            catch (FileNotFoundException)
            {
                MessageBox.Show("The program may be attempted, please obtain another copy of this program");
            }
            catch (Win32Exception)
            {
                MessageBox.Show("Help file not found, did you delete it?");
            }
            catch (ObjectDisposedException)
            {
                MessageBox.Show("The program may be attempted, please obtain another copy of this program");
            }
        }

        private void Reset()
        {
            listBox2.Items.Clear();

            listBox3.Items.Clear();

            dataGridView1.RowCount = 0;

            reading.Visible = true;

            label3.Text = "";

            Main.Visible = false;

            label5.Text = "";

            label7.Text = "";

            label9.Text = "";

            label11.Text = "";

            label14.Text = "";

            label15.Text = "";

            label18.Text = "";

            label19.Text = "";

            label23.Text = "";

            label24.Text = "";

            label27.Text = "";

            label28.Text = "";

            label29.Text = "";

            label32.Text = "";

            label35.Text = "";

            label33.Text = "";




            label37.Text = "";


            label39.Text = "";


            label41.Text = "";

            label43.Text = "";

            label47.Text = "";

            label48.Text = "";


            label49.Text = "";



            label59.Text = "";

            label60.Text = "";

            label62.Text = "";

            label63.Text = "";

            label64.Text = "";

            label65.Text = "";

            label66.Text = "";

            label67.Text = "";

            label70.Text = "";

            label71.Text = "";

            label72.Text = "";

            label73.Text = "";

            label76.Text = "";

            label77.Text = "";

            label79.Text = "";

            label81.Text = "";

            label83.Text = "";
            label87.Text = "";

            label89.Text = "";

            label91.Text = "";

            label93.Text = "";

            label95.Text = "";


            label97.Text = "";

            label99.Text = "";

            label101.Text = "";

            label103.Text = "";

            label107.Text = "";


            code.Text = "";

            richTextBox2.Text = "";

            label112.Text = "";

            label114.Text = "";

            label116.Text = "";
            label118.Text = "";
            label127.Text = "";
            label128.Text = "";
            label129.Text = "";
            label130.Text = "";
            label131.Text = "";
            label132.Text = "";
            label133.Text = "";

            ExportTable.RowCount = 0;
        }
    }
}
