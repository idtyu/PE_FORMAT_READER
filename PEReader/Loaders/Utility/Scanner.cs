/*
 * Admin NO: 100311M
 * Author: Yang JunHai
 * Date: 07/08/2012
 * Purpose: To read data according to the PE/COFF specification, be it one byte, two bytes, four bytes or eight bytes
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Loaders.Utility
{
    class Scanner
    {
        private int index;

        public int Index
        {
            get { return index; }
            set { index = value; }
        }
        byte[] text;

        public Scanner(int index,byte[] text)
        {
            this.index = index;
            this.text = text;
        }        
        
        public  byte readOneByte()
        {
            try
            {
                byte[] copyTo = new byte[1];
                Array.Copy(text, index, copyTo, 0, 1);
                index += 1;
                return copyTo[0];
            }
           
            catch (ArgumentOutOfRangeException)
            {
                return 0;
            }
            catch (ArgumentException)
            {
                return 0;
            }
          
            catch (Exception e)
            {
                throw e;
            }
            
        }

        public UInt16 readTwoBytes()
        {
            try
            {
                byte[] copyTo = new byte[2];
                Array.Copy(text, index, copyTo, 0, 2);
                index += 2;
                return BitConverter.ToUInt16(copyTo, 0);
            }

            catch (ArgumentOutOfRangeException)
            {
                return 0;
            }
            catch (ArgumentException)
            {
                return 0;
            }

            catch (Exception e)
            {
                throw e;
            }
        }

        public  UInt32 readFourBytes()
        {
            try
            {
                byte[] copyTo = new byte[4];
                Array.Copy(text, index, copyTo, 0, 4);
                index += 4;
                return BitConverter.ToUInt32(copyTo, 0);
            }

            catch (ArgumentOutOfRangeException)
            {
                return 0;
            }
            catch (ArgumentException)
            {
                return 0;
            }

            catch (Exception e)
            {
                throw e;
            }

        }

        public  UInt64 readEightBytes()
        {
            try
            {
                byte[] copyTo = new byte[8];
                Array.Copy(text, index, copyTo, 0, 8);
                index += 8;
                return BitConverter.ToUInt64(copyTo, 0);
            }
            catch (ArgumentOutOfRangeException)
            {
                return 0;
            }
            catch (ArgumentException)
            {
                return 0;
            }

            catch (Exception e)
            {
                throw e;
            }
        }
    }  
}
