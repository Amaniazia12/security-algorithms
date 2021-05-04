using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string alphabet = "abcdefghijklmnopqrstuvwxyz";
        public Dictionary<char, char> KeyTable(string key, string Operation)
        {
            Dictionary<char, char> TheKeyTable = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                if (Operation == "encrypt")
                    TheKeyTable.Add(alphabet[i], key[i]);
                else
                    TheKeyTable.Add(key[i], alphabet[i]);
            }
            return TheKeyTable;
        }


        public string Analyse(string plainText, string cipherText)
        {
            SortedDictionary<char, char> KeyTable = new SortedDictionary<char, char>();
            Dictionary<char, bool> alphaList = new Dictionary<char, bool>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string key = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                if (!KeyTable.ContainsKey(plainText[i]))
                {
                    KeyTable.Add(plainText[i], cipherText[i]);
                    alphaList.Add(cipherText[i], true);
                }
            }
            if (KeyTable.Count != 26)
            {
                for (int i = 0; i < 26; i++)
                {
                    if (!KeyTable.ContainsKey(alphabet[i]))
                    {
                        for (int j = 0; j < 26; j++)
                        {
                            if (!alphaList.ContainsKey(alphabet[j]))
                            {
                                KeyTable.Add(alphabet[i], alphabet[j]);
                                alphaList.Add(alphabet[j], true);
                                j = 26;
                            }
                        }
                    }
                }
            }
            for (int i = 0; i < KeyTable.Count; i++)
            {
                key += KeyTable.ElementAt(i).Value;
            }
            return key;

            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> keyTable = KeyTable(key, "decrypt");
            cipherText = cipherText.ToLower();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (char.IsLetter(cipherText[i]))
                    plainText += keyTable[cipherText[i]];
                else
                    plainText += cipherText[i];
            }
            return plainText;
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> keyTable = KeyTable(key, "encrypt");
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                if (char.IsLetter(plainText[i]))
                    cipherText += keyTable[plainText[i]];
                else
                    cipherText += plainText[i];
            }
            return cipherText.ToUpper();
            throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {

            string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            Dictionary<char, int> CAlphaFreq = new Dictionary<char, int>();
            SortedDictionary<char, char> keyTable = new SortedDictionary<char, char>();
            cipher = cipher.ToLower();
            string key = "";
            int counter = 0;
            for (int i = 0; i < cipher.Length; i++)
            {
                if (!CAlphaFreq.ContainsKey(cipher[i]))
                {
                    CAlphaFreq.Add(cipher[i], 0);
                }
                else
                {
                    CAlphaFreq[cipher[i]]++;
                }
            }
            CAlphaFreq = CAlphaFreq.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);

            foreach (var item in CAlphaFreq)
            {
                keyTable.Add(item.Key, alphabetFreq[counter]);
                counter++;
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                key += keyTable[cipher[i]];
            }
            return key;
            throw new NotImplementedException();
        }
    }
}
