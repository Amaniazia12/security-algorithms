using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {


        public string[,] arr = new string[5, 5];
        int col_indx = 0;
        int row_idx = -1;
        int[] ij_idx = new int[2];
        public PlayFair()
        {
            ij_idx[0] = -1;
            ij_idx[1] = -1;

        }
        int col_num = 0;
        int row_num = 0;

        bool ch = false;
        public string[,] fill_arr(string key)
        {


            string[] conv_2DarrTO_1D = new string[key.Length];


            for (int m = 0; m < key.Length; m++)
            {

                conv_2DarrTO_1D[m] = key[m].ToString();
            }

            int size = key.Length;
            for (int m = 0; m < size; m++)
            {

                for (int n = 0; n < m; n++)
                {
                    if (conv_2DarrTO_1D[n] == conv_2DarrTO_1D[m])
                    {

                        for (int p = m; p < size - 1; p++)
                        {
                            conv_2DarrTO_1D[p] = conv_2DarrTO_1D[p + 1];


                        }
                        size -= 1;

                    }


                }
            }



            for (int i = 0; i < size; i++)
            {

                if (i % 5 == 0)
                {
                    if (i != 0)
                    {
                        ch = true;
                    }


                    row_idx += 1;
                }
                col_indx = i % 5;


                arr[row_idx, col_indx] = conv_2DarrTO_1D[i].ToString().ToUpper();
                if (conv_2DarrTO_1D[i] == "i" || conv_2DarrTO_1D[i] == "I")
                {
                    arr[row_idx, col_indx] += "J";
                    ij_idx[0] = row_idx;
                    ij_idx[1] = col_indx;

                }
                else if (conv_2DarrTO_1D[i] == "j" || conv_2DarrTO_1D[i] == "J")
                {
                    arr[row_idx, col_indx] += "I";
                    ij_idx[0] = row_idx;
                    ij_idx[1] = col_indx;
                }



            }
            if (ch == true)
            {
                col_num = 5;
            }
            else
            {
                col_num = col_indx + 1;
            }
            row_num = row_idx + 1;

            bool find = false;
            int first_char = 65;
            int oo = col_indx + 1;
            for (int i = row_idx; i < 5; i++)
            {

                for (int j = oo; j < 5; j++)
                {
                    find = false;
                    while (true)
                    {
                        find = false;
                        for (int k = 0; k < size; k++)
                        {
                            if (((char)first_char).ToString().Equals(conv_2DarrTO_1D[k].ToUpper())
                                || (((char)first_char).ToString().Equals("I") && conv_2DarrTO_1D[k].ToUpper().Equals("J"))
                                || (((char)first_char).ToString().Equals("J") && conv_2DarrTO_1D[k].ToUpper().Equals("I")))
                            {
                                find = true;
                                break;

                            }

                        }
                        if (find == true)
                        {
                            first_char += 1;

                        }
                        else
                        {
                            if (((char)first_char).ToString() == "I")
                            {
                                arr[i, j] = ((char)first_char).ToString() + "J";
                                first_char += 2;
                                break;
                            }
                            else if (((char)first_char).ToString() == "J")
                            {
                                arr[i, j] = ((char)first_char).ToString() + "I";
                                first_char += 2;
                                break;
                            }
                            else
                            {
                                arr[i, j] = ((char)first_char).ToString();
                                first_char += 1;
                                break;
                            }

                        }

                    }
                }
                oo = 0;
            }
            return arr;
        }


        public string[] create_plain_OR_cipher(string plainText)
        {
            string[] ret = new string[2];
            string temp = "";
            string yes = "false";
            string yes_dub = "false";
            for (int i = 0; i < plainText.Length; i += 2)
            {
                yes_dub = "false";
                if (i == plainText.Length - 1)
                {
                    temp += plainText[i].ToString();
                    break;
                }

                if (plainText[i] == plainText[i + 1])
                {
                    temp += plainText[i].ToString() + "x";
                    yes_dub = "true";
                    i -= 1;
                }
                else
                {
                    temp += plainText[i].ToString() + plainText[i + 1].ToString();

                }



            }

            if (temp.Length % 2 != 0)
            {
                temp += "x";
                yes = "true";

            }

            plainText = temp;
            ret[0] = plainText;
            ret[1] = yes;

            return ret;
        }


        public string convert_cipherORplain_text(string text, string key)
        {

            bool is_encrypt = false;
            if ((int)text[0] >= 90 && (int)text[0] <= 122)
            {
                is_encrypt = true;
            }
            else
            {
                text = text.ToLower();
            }
            string converted_text = "";
            string[,] arr = fill_arr(key);
            text = create_plain_OR_cipher(text)[0];
            int[] arr_r = new int[2];
            int[] arr_c = new int[2];
            int index = 0;
            bool break_loop = false;
            bool IJ_check = false;
          
            while (index < text.Length)
            {
                break_loop = false;
            l1: for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (arr[i, j].Length > 1)
                        {
                            if ((text[index].ToString()).ToUpper().Equals(arr[i, j][0].ToString()) || (text[index].ToString()).ToUpper().Equals(arr[i, j][1].ToString()))
                            {

                                IJ_check = true;
                            }
                        }
                        if ((text[index].ToString()).ToUpper().Equals(arr[i, j]) || IJ_check == true)
                        {
                            arr_r[index % 2] = i;
                            arr_c[index % 2] = j;
                            index += 1;
                            IJ_check = false;




                            if (index % 2 != 0)
                            {

                                goto l1;


                            }
                            else
                            {


                                break_loop = true;

                                if (is_encrypt)
                                {
                                    if (arr_r[0] == arr_r[1])
                                    {
                                        if (arr_c[0] == 4)
                                        {
                                            if (arr[arr_r[0], 0].Length > 1)

                                                converted_text += arr[arr_r[0], 0][0].ToString();

                                            else
                                                converted_text += arr[arr_r[0], 0];
                                        }
                                        else if (arr_c[0] != 4)
                                        {
                                            if (arr[arr_r[0], arr_c[0] + 1].Length > 1)
                                                converted_text += arr[arr_r[0], arr_c[0] + 1][0].ToString();
                                            else
                                                converted_text += arr[arr_r[0], arr_c[0] + 1];
                                        }
                                        if (arr_c[1] == 4)
                                        {
                                            if (arr[arr_r[1], 0].Length > 1)
                                                converted_text += arr[arr_r[1], 0][0].ToString();
                                            else
                                                converted_text += arr[arr_r[1], 0];

                                        }
                                        else if (arr_c[1] != 4)
                                        {
                                            if (arr[arr_r[1], arr_c[1] + 1].Length > 1)
                                                converted_text += arr[arr_r[1], arr_c[1] + 1][0].ToString();
                                            else

                                                converted_text += arr[arr_r[1], arr_c[1] + 1];
                                        }

                                    }
                                    else if (arr_c[0] == arr_c[1])
                                    {
                                        if (arr_r[0] == 4)
                                        {
                                            if (arr[0, arr_c[0]].Length > 1)
                                                converted_text += arr[0, arr_c[0]][0].ToString();
                                            else
                                                converted_text += arr[0, arr_c[0]];
                                        }
                                        else if (arr_r[0] != 4)
                                        {
                                            if (arr[arr_r[0] + 1, arr_c[0]].Length > 1)
                                                converted_text += arr[arr_r[0] + 1, arr_c[0]][0].ToString();
                                            else
                                                converted_text += arr[arr_r[0] + 1, arr_c[0]];

                                        }
                                        if (arr_r[1] == 4)
                                        {
                                            if (arr[0, arr_c[1]].Length > 1)
                                                converted_text += arr[0, arr_c[1]][0].ToString();
                                            else
                                                converted_text += arr[0, arr_c[1]];

                                        }
                                        else if (arr_r[1] != 4)
                                        {
                                            if (arr[arr_r[1] + 1, arr_c[1]].Length > 1)
                                                converted_text += arr[arr_r[1] + 1, arr_c[1]][0].ToString();
                                            else
                                                converted_text += arr[arr_r[1] + 1, arr_c[1]];
                                        }





                                    }

                                    else
                                    {
                                        if (arr[arr_r[0], arr_c[1]].Length > 1)
                                            converted_text += arr[arr_r[0], arr_c[1]][0].ToString();
                                        else
                                            converted_text += arr[arr_r[0], arr_c[1]];

                                        if (arr[arr_r[1], arr_c[0]].Length > 1)
                                            converted_text += arr[arr_r[1], arr_c[0]][0].ToString();
                                        else
                                            converted_text += arr[arr_r[1], arr_c[0]];
                                    }
                                }


                             //decrypt

                                else
                                {


                                    if (arr_r[0] == arr_r[1])
                                    {
                                        if (arr_c[0] == 0)
                                        {
                                            if (arr[arr_r[0], 4].Length > 1)

                                                converted_text += arr[arr_r[0], 4][0].ToString();

                                            else
                                                converted_text += arr[arr_r[0], 4];
                                        }
                                        else if (arr_c[0] != 0)
                                        {
                                            if (arr[arr_r[0], arr_c[0] - 1].Length > 1)
                                                converted_text += arr[arr_r[0], arr_c[0] - 1][0].ToString();
                                            else
                                                converted_text += arr[arr_r[0], arr_c[0] - 1];
                                        }
                                        if (arr_c[1] == 0)
                                        {
                                            if (arr[arr_r[1], 4].Length > 1)
                                                converted_text += arr[arr_r[1], 4][0].ToString();
                                            else
                                                converted_text += arr[arr_r[1], 4];

                                        }
                                        else if (arr_c[1] != 0)
                                        {
                                            if (arr[arr_r[1], arr_c[1] - 1].Length > 1)
                                                converted_text += arr[arr_r[1], arr_c[1] - 1][0].ToString();
                                            else

                                                converted_text += arr[arr_r[1], arr_c[1] - 1];
                                        }

                                    }




                                    else if (arr_c[0] == arr_c[1])
                                    {
                                        if (arr_r[0] == 0)
                                        {
                                            if (arr[4, arr_c[0]].Length > 1)
                                                converted_text += arr[4, arr_c[0]][0].ToString();
                                            else
                                                converted_text += arr[4, arr_c[0]];
                                        }
                                        else if (arr_r[0] != 0)
                                        {
                                            if (arr[arr_r[0] - 1, arr_c[0]].Length > 1)
                                                converted_text += arr[arr_r[0] - 1, arr_c[0]][0].ToString();
                                            else
                                                converted_text += arr[arr_r[0] - 1, arr_c[0]];

                                        }
                                        if (arr_r[1] == 0)
                                        {
                                            if (arr[4, arr_c[1]].Length > 1)
                                                converted_text += arr[4, arr_c[1]][0].ToString();
                                            else
                                                converted_text += arr[4, arr_c[1]];

                                        }
                                        else if (arr_r[1] != 0)
                                        {
                                            if (arr[arr_r[1] - 1, arr_c[1]].Length > 1)
                                                converted_text += arr[arr_r[1] - 1, arr_c[1]][0].ToString();
                                            else
                                                converted_text += arr[arr_r[1] - 1, arr_c[1]];
                                        }





                                    }

                                    else
                                    {
                                        if (arr[arr_r[0], arr_c[1]].Length > 1)
                                            converted_text += arr[arr_r[0], arr_c[1]][0].ToString();
                                        else
                                            converted_text += arr[arr_r[0], arr_c[1]];

                                        if (arr[arr_r[1], arr_c[0]].Length > 1)
                                            converted_text += arr[arr_r[1], arr_c[0]][0].ToString();
                                        else
                                            converted_text += arr[arr_r[1], arr_c[0]];
                                    }

                                }

                                break;

                            }
                        }


                    }
                    if (break_loop == true)
                    {
                        break;
                    }
                }




            }
            if (is_encrypt)
                return converted_text;
            else
            {

                int[] idx_arr = new int[100];
                int idx = 0;

                if (converted_text[converted_text.Length - 1] == 'X' && create_plain_OR_cipher(text)[1].Equals("false"))
                    converted_text = converted_text.Substring(0, converted_text.Length - 1);


                for (int i = 0; i < converted_text.Length; i++)
                {
           
                    if (i > 0 && converted_text[i] == 'X' && converted_text[i - 1] == converted_text[i + 1] && i % 2 != 0)
                    {
                        idx_arr[idx] = i;
                        idx += 1;

                    }

                }


                int deleted_X_nums = 0;
                for (int j = 0; j < idx; j++)
                {
                    converted_text = converted_text.Remove(idx_arr[j] - deleted_X_nums, 1);
                    deleted_X_nums += 1;

                }



           


                return converted_text.ToLower();
            }
           



        }
        public string Decrypt(string cipherText, string key)
        {
            return convert_cipherORplain_text(cipherText, key);
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            return convert_cipherORplain_text(plainText, key);
            throw new NotImplementedException();
        }
    }
}
