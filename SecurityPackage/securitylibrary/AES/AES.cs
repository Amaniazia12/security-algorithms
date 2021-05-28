using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        struct arrKey
        {
            public String[,] roundkey;
        };
        arrKey[] _keySchedual = new arrKey[10];

        //public String[] Rcon = {
        //    "01", "00", "00", "00",
        //    "02", "00", "00", "00",
        //    "04", "00", "00", "00",
        //    "08", "00", "00", "00",
        //    "10", "00", "00", "00",
        //    "20", "00", "00", "00",
        //    "40", "00", "00", "00",
        //    "80", "00", "00", "00",
        //    "1b", "00", "00", "00",
        //    "36", "00", "00", "00"
        //};
        public String Rcon = "0x01000000020000000400000008000000100000002000000040000000800000001b00000036000000";

        public string mixCols = "0x02030101010203010101020303010102";
        //case string starts without 0x
        private static string[] SBOX = {
            "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
            "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
            "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
            "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
            "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
            "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
            "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
            "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
            "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
            "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
            "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
            "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
            "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
            "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
            "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
            "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"
        };
        //case string starts with 0x
        private static byte[] iSBOX = {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        };
        //Using this function in case the sbox is hexdecmial;

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {

            String[,] plainTextMatrix = new string[4, 4];
            String[,] cipherkey = new string[4, 4];

            //convert string to list 

            List<string> PT = ConvertStringToList(plainText);
            List<string> KT = ConvertStringToList(key);
            List<string> rconList = ConvertStringToList(Rcon);
            List<string> mixColList = ConvertStringToList(mixCols);


            //convert list to matrix 
            Console.WriteLine("plainText");
            plainTextMatrix = StringTomatrix(PT, 4, 4);
            Console.WriteLine("keycipher");
            cipherkey = StringTomatrix(KT, 4, 4);
            Console.WriteLine("Rcon");
            string[,] rconMatrix = StringTomatrix(rconList, 10, 4);
            Console.WriteLine("mixcol");
            string[,] mixColsMatrix = StringTomatrix(mixColList, 4, 4);

            //from hex to Bin
            //Console.WriteLine("BinaryplainText");
            plainTextMatrix = convertHexToBinMatrex(plainTextMatrix);
            Console.WriteLine("mixcol");
            mixColsMatrix = convertHexToBinMatrex(mixColsMatrix);
            // Done 

            //schedual
            keySchedual(cipherkey, rconMatrix, 10);
            //plainTextMatrix = SubByte(plainTextMatrix);

            plainTextMatrix = addRoundKey(plainTextMatrix, cipherkey);
            int sizeOfmatrix = getColumn(plainTextMatrix, 0).Length;

            // 9 main Round 
            for (int i = 0; i < 9; i++)
            {
                plainTextMatrix = convertBinToHexMatrex(plainTextMatrix);
                plainTextMatrix = SubByte(plainTextMatrix);
                plainTextMatrix = ShiftRows(plainTextMatrix);
                plainTextMatrix = convertHexToBinMatrex(plainTextMatrix);
                plainTextMatrix = MixColumns(plainTextMatrix, mixColsMatrix);
                plainTextMatrix = addRoundKey(plainTextMatrix, _keySchedual[i].roundkey);

            }
            //final Round
            plainTextMatrix = convertBinToHexMatrex(plainTextMatrix);
            plainTextMatrix = SubByte(plainTextMatrix);
            plainTextMatrix = ShiftRows(plainTextMatrix);
            plainTextMatrix = convertHexToBinMatrex(plainTextMatrix);
            plainTextMatrix = addRoundKey(plainTextMatrix, _keySchedual[9].roundkey);
            plainTextMatrix = convertBinToHexMatrex(plainTextMatrix);
            String cipher = convertMatrixToStrinf(plainTextMatrix, 4);
            Console.WriteLine(cipher);
            return cipher;

        }
        public string[] HexToDec(string[] x)
        {
            for (int i = 0; i < 4; i++)
            {
                x[i] = Convert.ToString(Convert.ToInt64(x[i], 16), 10);

            }
            return x;
        }
        public string[] Dect0Hex(string[] x)
        {
            for (int i = 0; i < 4; i++)
            {
                x[i] = Convert.ToString(Convert.ToInt64(x[i], 10), 16);

            }
            return x;
        }
        public string[] HexToBin(string[] x)
        {
            for (int i = 0; i < 4; i++)
            {
                x[i] = Convert.ToString(Convert.ToInt64(x[i], 16), 2);
                if (x[i].Length < 8)
                {
                    x[i] = new String('0', 8 - x[i].Length) + x[i];
                }
            }
            return x;
        }
        //location of the box at SBox
        public int BoxLocation(string str)
        {
            int Row = Convert.ToInt32(str[0].ToString(), 16);
            int strLength = Convert.ToInt32(str[1].ToString(), 16);
            int Position = Row * 16 + strLength;
            return Position;
        }

        public string[,] addRoundKey(string[,] plainText, string[,] roundKey)
        {
            int size = getColumn(plainText, 0).Length;

            String[] _columnOfPlainText = new string[4];
            String[] _columnOfRoundKey = new string[4];
            String[] _column = new string[4];

            for (int k = 0; k < size; k++)
            {

                for (int i = 0; i < 4; i++)
                {
                    _columnOfPlainText = getColumn(plainText, i);
                    _columnOfRoundKey = getColumn(roundKey, i);
                    for (int j = 0; j < 8; j++)
                        _column[i] += (_columnOfPlainText[i])[j] == (_columnOfRoundKey[i])[j] ? '0' : '1';

                }
                plainText = setColumn(plainText, _column, k);
                _column = new string[4];
            }
            Console.WriteLine(" addRound ");
            printMatrix(plainText);
            return plainText;
        }

        public List<string> ConvertStringToList(string x)
        {
            List<string> strList = new List<string>();
            string str = x.Split('x')[1];
            //string str = x.Split('x')[1];
            for (int i = 0; i < str.Length; i += 2)
            {
                strList.Add(str[i].ToString() + str[i + 1].ToString());
            }
            return strList;
        }
        public String[,] SubByte(String[,] plainText)
        {
            int size = getColumn(plainText, 0).Length;
            String[] _column = new string[4];

            for (int i = 0; i < size; i++)
            {
                _column = getColumn(plainText, i);

                for (int j = 0; j < size; j++)
                    _column[i] = SBOX[BoxLocation(plainText[i, j])];

                plainText = setColumn(plainText, _column, i);
            }

            Console.WriteLine("subByte");
            printMatrix(plainText);
            return plainText;
        }
        public string[,] ShiftRows(string[,] plainText)
        {
            int size = getColumn(plainText, 0).Length;
            plainText = setRow(plainText, getRow(plainText, 0), 0);
            for (int i = 1; i < size; i++)
            {
                String[] _tempRow = new String[4];
                String[] row = getRow(plainText, i);
                for (int j = 0; j < i; j++)
                    _tempRow[j] = row[j];

                for (int j = 0; j < size - i; j++)
                    row[j] = row[j + 1];

                for (int j = size - i; j < size; j++)
                    row[j] = _tempRow[j];
                plainText = setRow(plainText, getRow(plainText, i), i);
            }
            Console.WriteLine("ShiftRows");
            printMatrix(plainText);
            return plainText;
        }
        public string[,] MixColumns(string[,] plainText, String[,] mixCols)
        {
            int size = getColumn(plainText, 0).Length;
            string[] rowOfMixCols = new string[4];
            string[] columnOfPlainText = new string[4];
            String[] _column = new string[4];

            int res = 0;

            for (int k = 0; k < 4; k++)
            {
                for (int i = 0; i < 4; i++)
                {
                    rowOfMixCols = getRow(mixCols, i);
                    columnOfPlainText = getColumn(plainText, i);

                    for (int j = 0; j < size; j++)
                        res += Convert.ToInt32(rowOfMixCols[j], 2) * Convert.ToInt32(columnOfPlainText[j], 2);

                    _column[i] = Convert.ToString(res, 2);
                }
                plainText = setColumn(plainText, _column, k);
            }

            Console.WriteLine("mixColumn");
            printMatrix(plainText);
            return plainText;

        }
        public String[,] roundKey(string[,] cipherkey, string[] rcon)
        {
            int size = getColumn(cipherkey, 0).Length;
            string[,] roundKey = new String[4, 4];

            //lastColumn of round key  and it's process
            string[] lastColumn = new String[4];
            lastColumn = getColumn(cipherkey, size - 1);

            //subByte
            for (int i = 0; i < size; i++)
                lastColumn[i] = SBOX[BoxLocation(lastColumn[i])];

            //revers first element and last element 
            String temp = lastColumn[0];
            lastColumn[0] = lastColumn[size - 1];
            lastColumn[size - 1] = temp;

            //first column of round key 
            string[] firstColumn = new String[4];
            firstColumn = getColumn(cipherkey, 0);
            //rcon 
            string[] rconColumn = new String[4];

            // result OF Xor first col and last col  to create first column 

            lastColumn = HexToBin(lastColumn);
            firstColumn = HexToBin(firstColumn);
            rcon = HexToBin(rcon);

            string[] res = new String[4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                    res[i] += (firstColumn[i])[j] == (lastColumn[i])[j] ? "0" : "1";

                for (int j = 0; j < 8; j++)
                    roundKey[i, 0] += (res[i])[j] == (rcon[i])[j] ? "0" : "1";

            }

            //all culumns 
            String[] sec = getColumn(cipherkey, 1);
            String[] th = getColumn(cipherkey, 2);
            String[] frth = getColumn(cipherkey, 2);
            sec = HexToBin(sec);
            th = HexToBin(th);
            frth = HexToBin(frth);

            //sec column in round key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                    roundKey[i, 1] += (sec[i])[j] == (roundKey[i, 0])[j] ? "0" : "1";
            }
            //th column in round key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                    roundKey[i, 2] += (th[i])[j] == (roundKey[i, 1])[j] ? "0" : "1";
            }
            //frth column in round key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                    roundKey[i, 3] += (frth[i])[j] == (roundKey[i, 2])[j] ? "0" : "1";
            }

            Console.WriteLine("roundKey");
            printMatrix(cipherkey);
            return roundKey;
            //throw new NotImplementedException();
        }

        //araay of KeySchedual
        public void keySchedual(String[,] cipherkey, String[,] rcon, int numOfRoundKey)
        {

            String[] rconElement = getColumn(rcon, 0);


            _keySchedual[0].roundkey = convertHexToBinMatrex(cipherkey);

            for (int i = 1; i < 10; i++)
            {
                _keySchedual[i].roundkey = roundKey(_keySchedual[i - 1].roundkey, getRow(rcon, i - 1));
            }
            //return _keySchedual;
        }
        //Done
        public String[] getColumn(string[,] matrix, int position)
        {

            String[] _column = new string[matrix.Length / 4];

            for (int i = 0; i < 4; i++)
            {
                _column[i] = matrix[i, position];
            }
            return _column;
        }
        public String[] getRow(string[,] matrix, int position)
        {

            int lenght = matrix.Length;
            if (lenght > 16)
                lenght = 16;
            String[] _row = new string[lenght / 4];

            for (int i = 0; i < lenght / 4; i++)
            {
                _row[i] = matrix[position, i];
            }
            return _row;
        }
        //Done
        public String[,] setColumn(string[,] matrix, String[] column, int position)
        {
            int size = getColumn(matrix, 0).Length;
            for (int i = 0; i < size; i++)
            {
                matrix[i, position] = column[i];
            }
            return matrix;
        }
        public String[,] setRow(string[,] matrix, string[] row, int position)
        {
            int size = getColumn(matrix, 0).Length;
            for (int i = 0; i < size; i++)
            {
                matrix[position, i] = row[i];
            }
            return matrix;
        }
        //Done
        public void printMatrix(string[,] matrix)
        {
            string[] row = getRow(matrix, 0);
            string[] col = getColumn(matrix, 0);

            for (int i = 0; i < col.Length; i++)
            {
                for (int j = 0; j < row.Length; j++)
                {
                    Console.Write(matrix[i, j] + " ");
                }
                Console.WriteLine();
            }
            Console.WriteLine(" print matrix");
        }

        //Done
        public String[,] StringTomatrix(List<String> str, int row, int col)
        {
            String[,] matrix = new string[row, col];
            int k = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {

                    matrix[i, j] = str.ElementAt(k);
                    k++;
                }

            }
            printMatrix(matrix);
            return matrix;
        }

        public List<string> convertArrayToList(String[] arr, int sizOfmatrix)
        {
            List<string> list = new List<string>();
            for (int i = 0; i < sizOfmatrix; i++)
                list.Add(arr[i]);

            return list;
        }
        public string convertMatrixToStrinf(String[,] matrix, int size)
        {
            String str = "";
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    str += matrix[i, j];
                }
            }
            return str;
        }
        public string[,] convertHexToBinMatrex(String[,] matrix)
        {
            String[] _colmn = new string[4];

            for (int i = 0; i < 4; i++)
            {
                _colmn = getColumn(matrix, i);
                _colmn = HexToBin(_colmn);
                matrix = setColumn(matrix, _colmn, i);
            }
            return matrix;
        }

        public string[,] convertBinToHexMatrex(String[,] matrix)
        {

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[i, j] = BinaryStringToHexString(matrix[i, j]);
                }

            }
            return matrix;
        }

        public string binToHex(string a)
        {
            String res = " ";
            for (int i = 0; i <= 4; i += 4)
            {
                string aR = a[i].ToString() + a[i + 1].ToString() + a[i + 2].ToString() + a[i + 3].ToString();
                aR = Convert.ToInt32(aR, 2).ToString();
                aR = aR.Length == 1 ? aR :
                    aR == "10" ? "A" :
                    aR == "11" ? "B" :
                    aR == "12" ? "C" :
                    aR == "13" ? "D" :
                    aR == "14" ? "E" : "F";
                res += aR;
            }

            return res;
        }
        public static string BinaryStringToHexString(string binary)
        {
            if (string.IsNullOrEmpty(binary))
                return binary;

            StringBuilder result = new StringBuilder(binary.Length / 8 + 1);



            int mod4Len = binary.Length % 8;
            if (mod4Len != 0)
            {

                binary = binary.PadLeft(((binary.Length / 8) + 1) * 8, '0');
            }

            for (int i = 0; i < binary.Length; i += 8)
            {
                string eightBits = binary.Substring(i, 8);
                result.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
            }

            return result.ToString();
        }
    }

}
