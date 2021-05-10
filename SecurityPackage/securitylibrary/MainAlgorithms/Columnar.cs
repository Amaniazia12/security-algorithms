using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {


            int[] xx = new int[] { 1 };
            for (int i = 2; i < plainText.Length; i++)
            {
                var resulttt = new List<IList<int>>();

                xx = xx.Concat(new int[] { i }).ToArray();

                resulttt = DoPermute(xx, 0, xx.Length - 1, resulttt);
                //Console.WriteLine(resulttt.Count+ "   22");
                //Console.WriteLine($"    [{string.Join(',', resulttt)}]");
                foreach (List<int> resultt in resulttt)
                {
                    // Console.WriteLine($"    [{string.Join(',', resultt)}]");
                    string s = Encrypt(plainText, resultt);

                    Console.WriteLine(s);
                    //Console.WriteLine($"    [{string.Join(',', resultt)}]");
                    //Console.WriteLine(" 11 ");
                    if (s.Equals(cipherText.ToUpper()))
                    {
                        for (int k = 0; k < resultt.Count; k++)
                        {
                            resultt[k]++;

                        }
                        //Console.WriteLine($"    [{string.Join(',', resultt)}]");

                        return resultt;
                    }

                }

            }
            return new List<int>();
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();
            int max = 0;

            for (int i = 0; i < key.Count; i++)
            {
                key[i]--;
                if (max < key[i])
                    max = key[i];
            }
            int row = cipherText.Length / (max + 1);
            int x = 0;
            /**
            if (row * (max + 1) < cipherText.Length)
            {
                row++;
                x = row * (max + 1) - cipherText.Length;

            }
            **/
            //Console.WriteLine(row + " , " + max + "," + cipherText.Length + "," + x);
            string[,] mat = new string[20, max + 1];
            string outp = "";
            int indx = 0;
            for (int i = 0; i <= max; i++)
            {
                int y = key.IndexOf(i);
                //Console.WriteLine(y);
                for (int j = 0; j < row; j++)
                {
                    if (indx == cipherText.Length)
                    { mat[j, y] = "x"; }

                    /** if (j == row - 1 && i >= (max - x + 1))
                     {
                         mat[j, y] = " ";
                     }**/
                    else
                    {
                        mat[j, y] = cipherText[indx].ToString(); indx++;
                        // Console.WriteLine(indx + " index");
                    }

                    Console.WriteLine(mat[j, y].ToString() + ",");

                }
                Console.WriteLine(outp);
            }
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < max + 1; j++)
                {
                    outp += mat[i, j].ToString();
                    Console.Write(mat[i, j].ToString() + ",");
                }
                Console.WriteLine(" ");
            }

            Console.WriteLine(outp);
            return outp;
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {

            plainText = plainText.ToLower();
            int max = 0;
            for (int i = 0; i < key.Count; i++)
            {
                key[i]--;
                if (max < key[i])
                    max = key[i];
            }
            //Console.WriteLine(max);
            string[,] mat = new string[20, max + 1];
            int indx = 0;
            int row = 0;
            string outp = "";
            for (int i = 0; indx < plainText.Length; i++)
            {
                for (int j = 0; j <= max && indx < plainText.Length; j++)
                {
                    mat[i, j] = plainText[indx].ToString();
                    indx++;
                    //Console.Write(mat[i, j] + ",");
                }
                row++;
                //Console.WriteLine(" ");
            }
            for (int i = 0; i < max + 1; i++)
            {
                int y = key.IndexOf(i);
                //Console.WriteLine(y);
                for (int j = 0; j < row; j++)
                {
                    if (!(mat[j, y] == " "))
                        outp += mat[j, y];
                    else
                    {
                        outp += 'x';
                    }
                }
                // Console.WriteLine(outp);
            }
            // Console.WriteLine(outp);
            return outp.ToUpper();
            throw new NotImplementedException();
        }
        public List<IList<int>> DoPermute(int[] nums, int start, int end, List<IList<int>> list)
        {

            if (start == end)
            {
                // We have one of our possible n! solutions,
                // add it to the list.
                list.Add(new List<int>(nums));
            }
            else
            {
                for (var i = start; i <= end; i++)
                {
                    Swap(ref nums[start], ref nums[i]);
                    //Console.WriteLine( nums[start] + " ," +  nums[i]);
                    DoPermute(nums, start + 1, end, list);
                    //Console.WriteLine($"    [{string.Join(',', nums)}]");
                    Swap(ref nums[start], ref nums[i]);
                    //Console.WriteLine(nums[start] + " ,," + nums[i]);
                }
            }
            //PrintResult(list);
            return list;
        }

        static void Swap(ref int a, ref int b)
        {
            var temp = a;
            a = b;
            b = temp;
        }


    }
}

