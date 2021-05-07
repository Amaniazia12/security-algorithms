using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> Key = new List<int>();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            Key = new List<int>(new[] { i, j, k, l });
                            List<int> aa = Encrypt(plainText, Key);
                            if (aa.SequenceEqual(cipherText))
                            {
                                return Key;
                            }

                        }
                    }
                }
            }

            throw new InvalidAnlysisException();
        }

        public int det(double[,] K)
        {


            double A = K[0, 0] * (K[1, 1] * K[2, 2] - K[1, 2] * K[2, 1]) -
                  K[0, 1] * (K[1, 0] * K[2, 2] - K[1, 2] * K[2, 0]) +
                  K[0, 2] * (K[1, 0] * K[2, 1] - K[1, 1] * K[2, 0]);
            int AI = (int)A % 26 >= 0 ? (int)A % 26 : (int)A % 26 + 26;
            for (int i = 0; i < 26; i++)
            {
                if (AI * i % 26 == 1)
                {
                    return i;


                }

            }
            return -1;
        }

        public double[,] inverse(double[,]K,int det)
        {
            int end = (int)Math.Sqrt(K.Length);
            double[,] Ktemp = new double[end, end];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int x = i == 0 ? 1 : 0, y = j == 0 ? 1 : 0, x1 = i == 2 ? 1 : 2, y1 = j == 2 ? 1 : 2;
                    // Console.Write(K[x, y].ToString()+"   "+ K[x1, y1].ToString()+ "   "+K[x, y1].ToString()+ "   "+ K[x1, y].ToString()+ "   ");
                    double r = ((K[x, y] * K[x1, y1] - K[x, y1] * K[x1, y]) * Math.Pow(-1, i + j) * det) % 26;

                    Ktemp[i, j] = r >= 0 ? (int)r : (int)r + 26;

                }

            }






            for (int i = 0; i < end; i++)
            {
                for (int j = 0; j < end; j++)
                {

                    K[i, j] = Ktemp[i, j];

                }
            }


            for (int i = 0; i < end; i++)
            {
                for (int j = 0; j < end; j++)
                {

                    Ktemp[j, i] = K[i, j];

                }
            }










            return Ktemp;
        }
            
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            int end = (int)Math.Sqrt(key.Count);
            double[,] K = new double[end, end];
            double[,] Ktemp = new double[end, end];
            List<int> ans = new List<int>();
            int dett = 0;


            int m = 0;
            for (int i = 0; i < end; i++)
            {
                for (int j = 0; j < end; j++)
                {

                    K[i, j] = key[m];
                    m++;
                }
            }



            if (end == 3)
            {
                dett = det(K);
                if (dett == -1)
                    throw new SystemException();


                Ktemp = inverse(K, det(K));

            }


            else
            {
                double A = 1 / (K[0, 0] * K[1, 1] - K[0, 1] * K[1, 0]);
                int AI = (int)A % 26 >= 0 ? (int)A % 26 : (int)A % 26 + 26;
                for (int i = 0; i < 26; i++)
                {
                    if (AI * i % 26 == 1)
                    {
                        dett = i;
                        break;
                    }

                    dett = -1;
                }
                if (dett == -1)
                    throw new SystemException();


                double tmp = K[1, 1];
                K[1, 1] = K[0, 0];
                K[0, 0] = tmp;
                K[1, 0] = -1 * K[1, 0];
                K[0, 1] = -1 * K[0, 1];



                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        double r = (dett * K[i, j]) % 26;
                        Ktemp[i, j] = r >= 0 ? (int)r : (int)r + 26;
                    }
                }


            }


            m = 0;
            for (int k = 0; k < (int)cipherText.Count / end; k++)
            {
                for (int i = 0; i < end; i++)
                {
                    double sum = 0;
                    for (int j = 0; j < end; j++)
                    {
                        sum += Ktemp[i, j] * cipherText[m + j];
                    }
                    ans.Add(((int)sum % 26));
                }
                m += end;
            }
            for (int i = 0; i < cipherText.Count; i++)
                Console.WriteLine(ans[i]);
            return ans;


        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int end = (int)Math.Sqrt(key.Count);
            int[,] K = new int[end, end];
            List<int> ans = new List<int>();

            int m = 0;
            for (int i = 0; i < end; i++)
            {
                for (int j = 0; j < end; j++)
                {

                    K[i, j] = key[m];
                    m++;
                }
            }
            m = 0;
            for (int k = 0; k < (int)plainText.Count / end; k++)
            {
                for (int i = 0; i < end; i++)
                {
                    int sum = 0;
                    for (int j = 0; j < end; j++)
                    {
                        sum += K[i, j] * plainText[m + j];
                    }
                    ans.Add((sum % 26));
                }
                m += end;
            }

            return ans;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {

            int end = (int)Math.Sqrt(plainText.Count);
            double[,] PMatrix = new double[plainText.Count, plainText.Count];
            double[,] PD = new double[end , end];
            double[,] CD = new double[end , end];
            List<int> Key = new List<int>();

            int m = 0;
            for (int i = 0; i < end; i++)
            {
                for (int j = 0; j < end; j++)
                {
                    PD[j, i] = Convert.ToDouble(plainText[m]);
                    m++;
                }

            }


             m = 0;
            for (int i = 0; i < end; i++)
            {
                for (int j = 0; j < end; j++)
                {
                    CD[j, i] = Convert.ToDouble(cipherText[m]);
                    m++;
                }

            }


            

            PMatrix = inverse(PD, det(PD));




          for(int i = 0; i < 3; i++)
            {
                for(int j = 0; j < 3; j++)
                {
                    Console.WriteLine(PMatrix[i, j]);
                }
            }
            
            for (int k = 0; k < (int)plainText.Count / end; k++)
            {
                for (int i = 0; i < end; i++)
                {
                    int sum = 0;
                    for (int j = 0; j < end; j++)
                    {
                        sum +=(int)CD[k, j] * (int)PMatrix[j,i];
                    }
                    Key.Add((sum % 26));
                }
                
            }

            return Key;

        }

    }
}
