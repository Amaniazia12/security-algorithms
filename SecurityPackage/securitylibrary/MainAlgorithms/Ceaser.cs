using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public Monoalphabetic TheMonoalphabetic = new Monoalphabetic();
        public string Encrypt(string plainText, int key)
        {

            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                if (char.IsLetter(plainText[i]))
                {
                    for (int j = 0; j < TheMonoalphabetic.alphabet.Length; j++)
                        if (plainText[i] == TheMonoalphabetic.alphabet[j])
                        {
                            int Indx = ((key + j) % 26);
                            cipherText += TheMonoalphabetic.alphabet[Indx];
                        }
                }
                else
                {
                    cipherText += plainText[i];
                }
            }
            return cipherText.ToUpper();
       
            throw new NotImplementedException();
            
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (char.IsLetter(cipherText[i]))
                {
                    for (int j = 0; j < TheMonoalphabetic.alphabet.Length; j++)
                        if (cipherText[i] == TheMonoalphabetic.alphabet[j])
                        {
                            int Indx = ((j - key) % 26);
                            if (Indx < 0)
                                Indx += 26;
                            plainText += TheMonoalphabetic.alphabet[Indx];
                        }
                }
                else
                {
                    plainText += cipherText[i];
                }
            }
            return plainText;
           

            throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            
            int indx1 = 0, indx2 = 0;
            cipherText = cipherText.ToLower();
            if (plainText.Length != cipherText.Length) return -1;
            for (int i=0;i<TheMonoalphabetic.alphabet.Length;i++)
            {
                if (plainText[0] == TheMonoalphabetic.alphabet[i])
                    indx1 = i;
                if (cipherText[0] == TheMonoalphabetic.alphabet[i])
                    indx2 = i;
            }
            if ((indx2 - indx1) < 0)
                return (indx2 - indx1) + 26;
            else
                return (indx2 - indx1) % 26;
        
    
            throw new NotImplementedException();
        }
    }
}
