using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            List<float> SavingKey = new List<float>();
            float SK = 0;
            cipherText = cipherText.ToLower();
            int i = 1;
            int jj = 0;
            for (int j = 0; j < plainText.Length; j++)
            {
                // skip letters that shifted , num of letters equal to key num
                if (SavingKey.Count > 1 && SavingKey[SavingKey.Count - 1] == SavingKey[SavingKey.Count - 2])
                    break;
                if (cipherText[i] == plainText[j])
                {
                    jj = j;
                    i += 1;
                    SavingKey.Add(SK);

                    SK = 0;


                }
                SK++;

            }
            return ((int)SavingKey[SavingKey.Count - 1]);
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            float num_cols = (float.Parse(cipherText.Length.ToString()) / key);
            string fraction_letters = num_cols.ToString();
            int num_of_skips = int.Parse(Math.Ceiling(num_cols).ToString());

            for (int i = 0; i < num_of_skips; i++)
            {
                if (i == num_of_skips - 1 && fraction_letters.Length > 1 || i == cipherText.Length)
                {
                    plainText += cipherText[i].ToString();
                    break;
                }
                plainText += cipherText[i].ToString();
                for (int j = 0; j < key - 1; j++)
                {
                    if (i + num_of_skips * (j + 1) >= cipherText.Length)
                    {
                        break;
                    }

                    plainText += cipherText[i + num_of_skips * (j + 1)].ToString();
                }


            }
            return plainText.ToLower();
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            string[,] PlainMatrix = create_arr(plainText, key);
            string cipher = "";

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < num_col; j++)
                {

                    cipher += PlainMatrix[i, j];
                }
            }
            return cipher.ToUpper();

            throw new NotImplementedException();
        }

        public int num_col = 0;
        // convert plain text to matrix with depth(rows number) of the key

        public string[,] create_arr(string Text, int key)
        {
            float y = (float.Parse(Text.Length.ToString()) / key);
            int c = 0;
            num_col = int.Parse(Math.Ceiling(y).ToString());
            string[,] PlainMatrix = new string[key, num_col];
            string[,] PlainMatrix_FillGaps = new string[key, num_col];
            for (int j = 0; j < num_col; j++)
            {

                for (int i = 0; i < key; i++)
                {
                    if ((i + j * key) >= Text.Length)
                    {
                        c++;

                        PlainMatrix_FillGaps[i, j] = "x";


                    }
                    else
                    {
                        PlainMatrix[i, j] = Text[i + j * key].ToString();
                        PlainMatrix_FillGaps[i, j] = Text[i + j * key].ToString();
                    }
                }


            }
            if (c > 1)
            {
                return PlainMatrix_FillGaps;

            }
            else
                return PlainMatrix;

        }
    }
}
