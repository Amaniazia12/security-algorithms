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
        public string[,,] allkeys = new string[12, 4, 4];

        public string[,] rconMatrix = {
                { "00000001", "00000010", "00000100", "00001000", "00010000", "00100000", "01000000", "10000000", "00011011", "00110110"},
                { "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000"},
                { "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000"},
                { "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000"},

            };
        
        public String Rcon = "0x01000000020000000400000008000000100000002000000040000000800000001b00000036000000";

        public string mixCols = "0x02030101010203010101020303010102";
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
   
        public override string Decrypt(string cipherText, string key)
        {
            
            
            mixCols = mixCols.Remove(0, 2);
            string[,] mixcolsMatrix = StringTomatrix2(mixCols, 4, 4);
            cipherText = cipherText.Remove(0, 2);
            key = key.Remove(0, 2);
            string[,]  cipherTextMatrix = StringTomatrix(cipherText , 4 , 4);
            string[,] KeyMatrix = StringTomatrix(key, 4, 4);

            cipherTextMatrix = HexToBin(cipherTextMatrix);
            KeyMatrix = HexToBin(KeyMatrix);

            cipherTextMatrix = addRound(cipherTextMatrix, KeyMatrix);
            
            cipherTextMatrix = convertBinToHexMatrex(cipherTextMatrix);
            KeyMatrix = convertBinToHexMatrex(KeyMatrix);

            KeyMatrix = RoundKey(KeyMatrix, rconMatrix, 9);

            cipherTextMatrix = Shift(cipherTextMatrix);
            cipherTextMatrix = subByte(cipherTextMatrix);

            for (int i = 9; i > 0; i--)
            {
                cipherTextMatrix = HexToBin(cipherTextMatrix);

                for (int k = 0; k < 4; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        KeyMatrix[i, j] = allkeys[i, k, j];
                    }
                }
                KeyMatrix = HexToBin(KeyMatrix);
                cipherTextMatrix = addRound(cipherTextMatrix, KeyMatrix);
                cipherTextMatrix = convertBinToHexMatrex(cipherTextMatrix);
                KeyMatrix = HexToBin(KeyMatrix);
                KeyMatrix = RoundKey(KeyMatrix, rconMatrix, i);
                cipherTextMatrix = convertBinToHexMatrex(cipherTextMatrix);
                cipherTextMatrix = MixColumns(cipherTextMatrix, mixcolsMatrix);
                cipherTextMatrix = convertBinToHexMatrex(cipherTextMatrix);
                cipherTextMatrix = Shift(cipherTextMatrix);
                cipherTextMatrix = subByte(cipherTextMatrix); 
            }
            KeyMatrix = HexToBin(KeyMatrix);
            cipherTextMatrix = convertBinToHexMatrex(cipherTextMatrix);
            for (int k = 0; k < 4; k++)
            {
                for (int j = 0; j < 4; j++)
                {
                    KeyMatrix[0, j] = allkeys[0, k, j];
                }
            }
            cipherTextMatrix = addRound(cipherTextMatrix,KeyMatrix );
            KeyMatrix = convertBinToHexMatrex(KeyMatrix);
            cipherTextMatrix = convertBinToHexMatrex(cipherTextMatrix);
            
            string plainText = "0x";
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    plainText += cipherTextMatrix[i, j];
                }
            }

            return plainText; 
        }

        public override string Encrypt(string plainText, string key)
        {
            
            plainText = plainText.Remove(0, 2);
            key = key.Remove(0, 2);
            mixCols = mixCols.Remove(0, 2);
            Rcon = Rcon.Remove(0, 2);

            string[,] plaintextMatrix = StringTomatrix(plainText, 4, 4);
            string[,] keyMatrix = StringTomatrix(key, 4, 4);
            for (int i = 0; i < 4; i ++)
            {
                for (int j = 0; j < 4; j ++)
                {
                    allkeys[0, i, j] = keyMatrix[i, j];
                }
            }
            string[,] mixcolsMatrix = StringTomatrix2(mixCols, 4, 4);

            mixcolsMatrix = HexToBin(mixcolsMatrix);
            plaintextMatrix = HexToBin(plaintextMatrix);
            keyMatrix = HexToBin(keyMatrix);
            plaintextMatrix = addRound(plaintextMatrix, keyMatrix);
            plaintextMatrix = convertBinToHexMatrex(plaintextMatrix);
            keyMatrix = convertBinToHexMatrex(keyMatrix);


            for (int i = 0; i < 9; i++)
            {
                plaintextMatrix = subByte(plaintextMatrix);
                plaintextMatrix = Shift(plaintextMatrix);

                plaintextMatrix = HexToBin(plaintextMatrix);
                plaintextMatrix = MixColumns(plaintextMatrix, mixcolsMatrix);
                plaintextMatrix = convertBinToHexMatrex(plaintextMatrix);

                keyMatrix = RoundKey(keyMatrix, rconMatrix, i);
                keyMatrix = HexToBin(keyMatrix);
                plaintextMatrix = HexToBin(plaintextMatrix);
                plaintextMatrix = addRound(plaintextMatrix, keyMatrix);
                keyMatrix = convertBinToHexMatrex(keyMatrix);
                plaintextMatrix = convertBinToHexMatrex(plaintextMatrix);
            }

            plaintextMatrix = subByte(plaintextMatrix);
            plaintextMatrix = Shift(plaintextMatrix);

            keyMatrix = RoundKey(keyMatrix, rconMatrix, 9);

            keyMatrix = HexToBin(keyMatrix);
            plaintextMatrix = HexToBin(plaintextMatrix);
            plaintextMatrix = addRound(plaintextMatrix, keyMatrix);
            plaintextMatrix = convertBinToHexMatrex(plaintextMatrix);

            string cipher = "0x";
            for (int j = 0; j < 4; j++)
                for (int i = 0; i < 4; i++)
                    cipher += plaintextMatrix[i, j];

            return cipher;

        }

        public int BoxLocation(string str)
        {
            int Row = Convert.ToInt32(str[0].ToString(), 16);
            int strLength = Convert.ToInt32(str[1].ToString(), 16);
            int Position = Row * 16 + strLength;
            return Position;
        }
        public string [,] subByte (string [, ] plainText)
        {

            for (int i = 0; i < 4; i++)
            { 
                for (int j = 0; j < 4; j++)
                    plainText[i,j]= SBOX[BoxLocation(plainText[i, j])];
            }

            return plainText;
        }
        string[,] ShiftRow(string[,] plainText, int r)
        {
            string first = plainText[r, 0];
            for (int i = 0; i < 3; i++)
                plainText[r, i] = plainText[r, i + 1];
            plainText[r, 3] = first;
            return plainText;
        }
        public string [,] Shift (string [,] plainText)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    ShiftRow(plainText, i);
                }
            }
            return plainText;
        }
        public string [, ] MixColumns(string [,] plainText , string [, ] mixCols)
        {
            string[,] Matrix = new string[4, 4];
            for (int rIdx = 0; rIdx < 4; rIdx++)
            {
                for (int cIdx = 0; cIdx < 4; cIdx++)
                {
                    string res = "00000000";
                    for (int i = 0; i < 4; i++)
                    {
                        if (mixCols[rIdx, i] == "00000001")
                        {
                            res = Xor(res, plainText[i, cIdx]);
                        }
                        else if (mixCols[rIdx, i] == "00000010")
                        {
                            string ans = mult(plainText[i, cIdx]);
                            res = Xor(res, ans);
                        }
                        else if (mixCols[rIdx, i] == "00000011")
                        {
                            string ans = mult(plainText[i, cIdx]);
                            ans = Xor(ans, plainText[i, cIdx]);
                            res = Xor(res, ans);
                        }
                    }
                    Matrix[rIdx, cIdx] = res;
                }
            }
            return Matrix;
        }
        public string [, ] addRound(string [, ] plainText , string [, ] cipherKey )
        {
            for (int i= 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plainText[i, j] = Xor(cipherKey[i, j], plainText[i, j]);
                }
            }
            return plainText;
        }
        public string[,] addRoundDecrypt(string[,] plainText, string[,] cipherKey)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plainText[i, j] = Xor(cipherKey[i, j], plainText[i, j]);
                }
            }
            return plainText;
        }
        public string[,] RoundKey(string[,] roundkey, string[,] rcon, int index)
        {
            string[] col = new string[4];
            for (int i = 0; i < 4; i++)
            {
                col[i] = roundkey[i, 3];

            }
            for (int i = 0; i < 4; i++)
                col[i] = SBOX[BoxLocation(col[i])];

            string first = col[0];
            for (int i = 0; i < 3; i++)
                col[i] = col[i + 1];
            col[3] = first;

            for (int i = 0; i < 4; i++)
            {
                roundkey[i, 0] = Xor(hexto(roundkey[i, 0]), hexto(col[i]));
                roundkey[i, 0] = Xor(roundkey[i, 0], rcon[i, index]);
            }

            for (int j = 1; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string str = roundkey[i, j - 1];
                    roundkey[i, j] = Xor(hexto(roundkey[i, j]), str);
                }
            }
            roundkey = convertBinToHexMatrex(roundkey);

            
            return roundkey;
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
        public string mult(string str)
        {
            char c = str[0];
            str = str.Remove(0, 1);
            str += '0';
            if (c == '1')
            {
                str = Xor(str, "00011011");
            }
            return str;
        }
        public string Xor(string str1, string str2)
        {
            string res = "";
            for (int i = 0; i < 8; i++)
                if (str1[i] == str2[i])
                    res += '0';
                else res += '1';
            return res;
        }
       
        public String[,] StringTomatrix(String str, int row, int col)
        {
            String[,] matrix = new string[row, col];
            int idx = 0;
            for (int j = 0; j < col; j++)
            {
                for (int i = 0; i < row; i++)
                {

                    matrix[i, j] = str[idx].ToString() + str[idx + 1].ToString();
                    idx += 2;
                    
                }

            }
            //printMatrix(matrix);
            return matrix;
        }
        public String[,] StringTomatrix2(String str, int row, int col)
        {
            String[,] matrix = new string[row, col];
            int idx = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {

                    matrix[i, j] = str[idx].ToString() + str[idx + 1].ToString();
                    idx += 2;

                }

            }
            //printMatrix(matrix);
            return matrix;
        }
        public String[,] StringTomatrix3(String str, int row, int col)
        {
            String[,] matrix = new string[row, col];
            int idx = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {

                    matrix[i, j] = str[idx].ToString() + str[idx + 1].ToString();
                    idx += 2;

                }

            }
            //printMatrix(matrix);
            return matrix;
        }
        public string hexto(string str) {
            str = Convert.ToString(Convert.ToInt64(str, 16), 2);
            if (str.Length < 8)
            {
                str = new string('0', 8 - str.Length) + str;
            }
            return str;
        } 
        public string[,] HexToBin(string[,] matrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[i, j] = hexto(matrix[i, j]);
                }
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

        

    }

}