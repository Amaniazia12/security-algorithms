using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char[,] matr = Matricx2D();
            int jj = 0;
            string outp = "";
            int x = 0, y = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                //int x = 0, y = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (matr[0, j].Equals(plainText[i]))
                    {
                        x = j;
                        break;
                    }
                }
                //Console.WriteLine("11");

                for (int j = 0; j < 26; j++)
                {
                    if (matr[j, x].Equals(cipherText[i]))
                    {
                        y = j;
                        outp += matr[y, 0];
                        break;
                    }
                }
            }
            int index=0;
            for(int i = outp.Length-1; i > 0; i--)
            {
     
                string C = Encrypt(plainText, outp.Substring(0, i));
                if (C.Equals(cipherText.ToUpper()))
                {
                    index = i;
                }
            }
      
            Console.WriteLine(outp.Substring(0, index));
            return outp.Substring(0, index);
           
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            char[,] matr = Matricx2D();
            int len = 0;
            string str = key;
            string outp = "";
            int xx = 0;
            for (int i = 0; str.Length < cipherText.Length; i++, xx++)
            {
                if (xx == key.Length)
                {
                    xx = 0;
                }
                str += key[xx].ToString();
            }
            Console.WriteLine(str);
            for (int i = 0; i < cipherText.Length; i++)
            {
                int x = 0, y = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (matr[0, j].Equals(str[i]))
                    {
                        x = j;
                        break;
                    }
                }
                //Console.WriteLine("11");

                for (int j = 0; j < 26; j++)
                {
                    if (matr[j, x].Equals(cipherText[i]))
                    {
                        y = j;
                        outp += matr[y, 0];
                        break;
                    }
                }
                //Console.WriteLine("22" );

                Console.WriteLine(outp);
            }

            return outp.ToUpper();
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            char[,] matr = Matricx2D();
            int len = 0;
            string str = key;
            string outp = "";
            int xx = 0;
            for (int i = 0; str.Length < plainText.Length; i++, xx++)
            {
                if (xx == key.Length)
                {
                    xx = 0;
                }
                str += key[xx].ToString();
            }
            //Console.WriteLine(str);
            for (int i = 0; i < plainText.Length; i++)
            {
                int x = 0, y = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (matr[0, j].Equals(str[i]))
                    {
                        x = j;
                        break;
                    }
                }
                //Console.WriteLine("11");

                for (int j = 0; j < 26; j++)
                {
                    if (matr[j, 0].Equals(plainText[i]))
                    {
                        y = j;
                        break;
                    }
                }
                //Console.WriteLine("22" );
                outp += matr[x, y];
                //Console.WriteLine(outp);
            }

            return outp.ToUpper();
            throw new NotImplementedException();
        }

        public char[,] Matricx2D()
        {
            char[,] matrix = new char[26, 26];
            int x_constatnt = 97;
            int x = 97;
            for (int i = 0; i < 26; i++)
            {
                x = x_constatnt;
                for (int j = 0; j < 26; j++)
                {
                    if (x == 123)
                    {
                        x = 97;
                    }
                    matrix[i, j] = (char)x;
                    x++;
                    //Console.Write(matrix[i, j] + " , ");
                }
                x_constatnt++;
                //Console.WriteLine("\n");
            }
            return matrix;
        }
    }
}