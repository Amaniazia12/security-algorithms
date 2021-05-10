using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char[,] matr = Matricx2D();
            int jj = 0;
            string outp = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (matr[0, j].Equals(plainText[i]))
                    {
                        jj = j;
                        break;
                    }
                }
                for (int j = 0; j < 26; j++)
                {
                    if (matr[jj, j].Equals(cipherText[i]))
                    {

                        outp += matr[j, 0];
                        break;
                    }
                }

            }

           // Console.WriteLine(outp);
            bool found = false;
            int w = 1, index = 0;
            for (int i = 0; i < outp.Length; i++)
            {
                if (outp[i].Equals(plainText[0]))
                {
                    found = true;
                    index = i;
                    //Console.WriteLine(outp[i]);
                    for (int j = i; j < outp.Length && found == true; j++)
                    {
                        if (!outp[j].Equals(plainText[w]))
                        {
                            //Console.WriteLine("2222" +outp[i]);
                            found = false;
                            w = 1;
                            i = j;
                        }
                        w++;
                    }
                }
            }

            Console.WriteLine(outp.Substring(0, index));
            return outp.Substring(0, index);
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] matr = Matricx2D();
            int len = 0;

            string plainText = "";
            cipherText = cipherText.ToLower();

            for (int i = 0; i < cipherText.Length; i++)
            {
                int x = 0, y = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (matr[0, j].Equals(key[i]))
                    {
                        x = j;
                        break;
                    }
                }
                //Console.WriteLine(x);
                for (int h = 0; h < 26; h++)
                {
                    if (matr[h, x].Equals(cipherText[i]))
                    {
                        y = h;
                        key += matr[y, 0];
                        plainText += matr[y, 0];
                        break;
                    }
                }
            }

            Console.WriteLine(plainText);
            return plainText;
 
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            char[,] matr = Matricx2D();
            int len = 0;
            string str = key;
            string outp = "";
            for (int i = 0; str.Length < plainText.Length; i++)
            {
                str += plainText[i].ToString();
            }

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
