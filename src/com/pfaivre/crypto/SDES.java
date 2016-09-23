/*
 * SDES
 * Pierre Faivre
 *
 * SDES.java
 * Creation : 30/03/2016
 * Last modification : 23/09/2016
 */

package com.pfaivre.crypto;

import java.io.*;
import java.util.ArrayList;

/**
 * S-DES algorithm implementation
 * This class can handle the encryption and decryption of a file
 */
public class SDES {
    /**
     * Main key
     */
    private boolean[] master_key;

    /**
     * Subkey 1
     */
    private boolean[] K1;

    /**
     * Subkey 2
     */
    private boolean[] K2;

    /**
     * S-Box 0
     */
    private static boolean[][][] S0 = new boolean[][][]
        {{{false, true},  {false, false}, {true,  true}, {true,  false}},
         {{true,  true},  {true,  false}, {false, true}, {false, false}},
         {{false, false}, {true,  false}, {false, true}, {true,  true}},
         {{true,  true},  {false, true},  {true,  true}, {true,  false}}};

    /**
     * S-Box 1
     */
    private static boolean[][][] S1 = new boolean[][][]
        {{{false, false}, {false, true},  {true,  false}, {true,  true}},
         {{true,  false}, {false, false}, {false, true},  {true,  true}},
         {{true,  true},  {false, false}, {false, true},  {false, false}},
         {{true,  false}, {false, true},  {false, false}, {true,  true}}};

    /**
     * Instanciate a new instance of SDES to perform encryption or decrytion operations.
     * @param key 10-bit key. For example "0110100111"
     */
    public SDES(String key) {
        master_key = new boolean[10];

//        if (key.length() != 10)
//            throw new Exception("The key must be of the size of 10 bits.");

        for (int i = 0 ; i < key.length() ; i++) {
            if (key.charAt(i) == '0')
                this.master_key[i] = false;
            else if (key.charAt(i) == '1')
                this.master_key[i] = true;
//            else
//                throw new Exception("The key can only contain '0' or '1'.");
        }

        ArrayList<boolean[]> keys = SDES.generateKeys(this.master_key);
        this.K1 = keys.get(0);
        this.K2 = keys.get(1);
    }

    // ###############################
    // Generation of subkeys K1 and K2
    // ###############################

    /**
     * Performs a P10 permutation
     * P10(k1, k2, k3, k4, k5, k6, k7, k8, k9, k10) = (k3, k5, k2, k7, k4, k10, k1, k9, k8, k6)
     * @param input 10-bit sequence to transform
     * @return an array of 8 booleans
     */
    static boolean[] p10(boolean[] input) {
        boolean[] output = new boolean[10];

        // This is an abitrary permutation, it needs to be done by hand
        output[0] = input[2];
        output[1] = input[4];
        output[2] = input[1];
        output[3] = input[6];
        output[4] = input[3];
        output[5] = input[9];
        output[6] = input[0];
        output[7] = input[8];
        output[8] = input[7];
        output[9] = input[5];

        return output;
    }

    /**
     * Performs a P8 permutation
     * P8(k1, k2, k3, k4, k5, k6, k7, k8) = (k6, k3, k7, k4, k8, k5, k10, k9)
     * @param input 8-bit sequence to transform
     * @return an array of 8 booleans
     */
    static boolean[] p8(boolean[] input) {
        boolean[] output = new boolean[8];

        // This is an abitrary permutation, it needs to be done by hand
        output[0] = input[5];
        output[1] = input[2];
        output[2] = input[6];
        output[3] = input[3];
        output[4] = input[7];
        output[5] = input[4];
        output[6] = input[9];
        output[7] = input[8];

        return output;
    }

    /**
     * Rotates all the bits of each half of the sequence to the left
     * For example : 10000 01100 becomes 00001 11000 with a shift of 1 bit.
     * @param input 10-bit sequence to transform
     * @param offset number of times the rotation is performed
     */
    static boolean[] circularLeftShift(boolean[] input, int offset) {
        // Splits in two halves of 5 bits
        boolean[] leftHalf = new boolean[5];
        boolean[] rightHalf = new boolean[5];

        // Rotates to the left
        for (int i = 0 ; i < 5 ; i++) {
            leftHalf[5 - (((5 - i - 1) + offset) % 5) - 1] = input[i];
            rightHalf[5 - (((5 - i - 1) + offset) % 5) - 1] = input[i + 5];
        }

        // Gathering of the two halves
        boolean[] output = new boolean[10];
        System.arraycopy(leftHalf, 0, output, 0, leftHalf.length);
        System.arraycopy(rightHalf, 0, output, 5, rightHalf.length);

        return output;
    }

    /**
     * Generates the two subkeys from the main one
     * @param master_key 10-bit main key
     * @return ArrayList containing in index 0 => K1 and in index 1 => K2
     */
    static ArrayList<boolean[]> generateKeys(boolean[] master_key) {
        // master_key => p10 => circularLeftShift(1) => p8 => K1
        boolean[] K1 = p8(circularLeftShift(p10(master_key), 1));

        // master_key => p10 => circularLeftShift(3) => p8 => K2
        boolean[] K2 = p8(circularLeftShift(p10(master_key), 3));

        ArrayList<boolean[]> keys = new ArrayList<>();
        keys.add(K1);
        keys.add(K2);
        return keys;
    }

    // ###################################
    // Encryption and decryption functions
    // ###################################

    /**
     * Performs an Initial Permutation (IP) on a byte
     * IP(k1, k2, k3, k4, k5, k6, k7, k8) = (k2, k6, k3, k1, k4, k8, k5, k7)
     * @param input Byte to transform
     * @return transformed byte
     */
    static boolean[] ip(boolean[] input) {
        boolean[] output = new boolean[8];

        // This is an abitrary permutation, it needs to be done by hand
        output[0] = input[1];
        output[1] = input[5];
        output[2] = input[2];
        output[3] = input[0];
        output[4] = input[3];
        output[5] = input[7];
        output[6] = input[4];
        output[7] = input[6];

        return output;
    }

    /**
     * Performs an Reversed Initial Permutation (RIP or IP-1) on a byte
     * IP−1(k1, k2, k3, k4, k5, k6, k7, k8) = (k4, k1, k3, k5, k7, k2, k8, k6)
     * Note that IP ans RIP are defined so x = RIP(IP(x))
     * @param input Byte to transform
     * @return transformed byte
     */
    static boolean[] rip(boolean[] input) {
        boolean[] output = new boolean[8];

        // This is an abitrary permutation, it needs to be done by hand
        output[0] = input[3];
        output[1] = input[0];
        output[2] = input[2];
        output[3] = input[4];
        output[4] = input[6];
        output[5] = input[1];
        output[6] = input[7];
        output[7] = input[5];

        return output;
    }

    /**
     * Performs an Expansion/Permutation (E/P) operation on a 4-bit word
     * E/P(n1, n2, n3, n4) = (n4, n1, n2, n3, n2, n3, n4, n1)
     * @param input 4-bit word to transform
     * @return 8-bit (byte) resulting of the operation
     */
    static boolean[] ep(boolean[] input) {
        boolean[] output = new boolean[8];

        // This is an abitrary permutation, it needs to be done by hand
        output[0] = input[3];
        output[1] = input[0];
        output[2] = input[1];
        output[3] = input[2];
        output[4] = input[1];
        output[5] = input[2];
        output[6] = input[3];
        output[7] = input[0];

        return output;
    }

    /**
     * Performs an exlusif or (XOR) operation on two words
     * Both operands must have the same number of bits
     * @param a Operand 1
     * @param b Operand 2
     * @return result
     */
    static boolean[] xor(boolean[] a, boolean[] b) {
        boolean[] output = new boolean[a.length];

        for (int i = 0 ; i < a.length ; i++)
            output[i] = a[i] ^ b[i];

        return output;
    }

    /**
     * Transforms a byte by using the S-Boxes as correspondence table
     * @param input An 8-bit word
     * @return A 4-bit word resulting of the transformation
     */
    static boolean[] sboxTransform(boolean[] input) {
        int i, j = 0;

        // Left half with S0

        // The 1st and 4th bits give the index of the row
        i = (input[0] ? 2 : 0) + (input[3] ? 1 : 0);
        // The 2nd and 3rd bits give the index of the column
        j = (input[1] ? 2 : 0) + (input[2] ? 1 : 0);

        // These indexes point to a cell of S0 whose value is taken
        boolean[] s0Result = S0[i][j];

        // Right half with S1

        // The 5th and 8th bits give the index of the row
        i = (input[4] ? 2 : 0) + (input[7] ? 1 : 0);
        // The 6th and 7th bits give the index of the column
        j = (input[5] ? 2 : 0) + (input[6] ? 1 : 0);

        // These indexes point to a cell of S1 whose value is taken
        boolean[] s1Result = S1[i][j];

        // Finally we gather the given results in a 4-bit word
        return new boolean[] {s0Result[0], s0Result[1], s1Result[0], s1Result[1]};
    }

    /**
     * Performs a P4 permutation
     * P4(k1, k2, k3, k4) = (k2, k4, k3, k1)
     * @param input 4-bit word to transform
     * @return 4-bit word resulting of the transformation
     */
    static boolean[] p4(boolean[] input) {
        boolean[] output = new boolean[4];

        // This is an abitrary permutation, it needs to be done by hand
        output[0] = input[1];
        output[1] = input[3];
        output[2] = input[2];
        output[3] = input[0];

        return output;
    }

    /**
     * Encryption transformation sub-function
     * @param right right half of the byte to transform
     * @param sk Subkey K1 or K2
     * @return a sequence of 4 bits
     */
    static boolean[] f(boolean[] right, boolean[] sk) {
        // We apply E/P on right
        // We perform a XOR between the given result and the subkey
        // We pass the result through the S-Boxes
        // Finally we "shuffle" with P4 and return it
        return p4(sboxTransform(xor(ep(right), sk)));
    }

    /**
     * fK transformation
     * @param bits 8-bit sequence given by IP or RIP
     * @param sk Subkey K1 or K2
     * @return a sequence of 8 bits
     */
    static boolean[] fK(boolean[] bits, boolean[] sk) {
        // We perform a XOR between the left half and the result of f(right)
        // We concatenate the 4 bits of the original right with the result above
        // We return this concatenation

        // Split in two halves
        boolean[] left = new boolean[4];
        boolean[] right = new boolean[4];
        System.arraycopy(bits, 0, left, 0, left.length);
        System.arraycopy(bits, 4, right, 0, right.length);

        // = left XOR f(right, SK)
        boolean[] transformed = xor(left, f(right, sk));

        // = concat(transformed, right)
        boolean[] output = new boolean[8];
        System.arraycopy(transformed, 0, output, 0, transformed.length);
        System.arraycopy(right, 0, output, 4, right.length);

        return output;
    }

    /**
     * Swaps the two halves of a byte
     * For exemple, 11110000 becomes 00001111
     * @param input Byte to transform
     * @return Byte resulting
     */
    static boolean[] sw(boolean[] input) {
        boolean[] output = new boolean[8];
        System.arraycopy(input, 4, output, 0, 4);
        System.arraycopy(input, 0, output, 4, 4);

        return output;
    }

    /**
     * Converts a byte into a boolean array
     * @param block Byte to transcript
     * @return Array of 8 booleans
     */
    static boolean[] byte2bool(byte block) {
        boolean[] result = new boolean[8];

        // Let's run through the bits individually
        for (int i = 0 ; i < 8 ; i++) {
            // Slice the bit at the position i in the byte
            int b = ((block >> i) & 1);

            // And insert it in the array in the form of a boolean
            result[7 - i] = b == 1;
        }

        return result;
    }

    /**
     * Converts a boolean array into a byte
     * @param block An array of 8 booleans
     * @return The resulting byte
     */
    static byte bool2byte(boolean[] block) {
        byte result = 0b00000000;

        // For each boolean (bit) of the array
        for (int i = 0 ; i < block.length ; i++) {
            // We "print" it at the end of the byte
            result = (byte)(result | (block[i] ? 1 : 0));

            // And we shift the previous bits to the left to let space for the next one
            if (i < block.length - 1)
                result = (byte)(result << 1);
        }

        return result;
    }

    /**
     * Encrypts a data block
     * @param block A plain byte to encrypt
     * @return The resulting byte
     */
    @SuppressWarnings("Duplicates")
    byte encrypt(byte block) {
        boolean[] tmp = byte2bool(block);

        tmp = ip(tmp);
        tmp = fK(tmp, this.K1);
        tmp = sw(tmp);
        tmp = fK(tmp, this.K2);
        tmp = rip(tmp);

        return bool2byte(tmp);
    }

    /**
     * Decrypts a data block
     * @param block A byte to decrypt
     * @return The resulting plain byte
     */
    @SuppressWarnings("Duplicates")
    byte decrypt(byte block) {
        boolean[] tmp = byte2bool(block);

        tmp = ip(tmp);
        tmp = fK(tmp, this.K2);
        tmp = sw(tmp);
        tmp = fK(tmp, this.K1);
        tmp = rip(tmp);

        return bool2byte(tmp);
    }

    /**
     * Encrypts a file
     * Its content will be ciphered by blocks of one byte
     * @param inputFile Path to the file to read
     * @param outputFile Path to the file to write
     */
    public void encryptFile(File inputFile, File outputFile) throws IOException {
        FileInputStream input = null;
        FileOutputStream output = null;

        try {
            input = new FileInputStream(inputFile);
            output = new FileOutputStream(outputFile);

            int c = -1;
            while ((c = input.read()) != -1) {
                output.write(this.encrypt((byte)c));
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            if (input != null)
                input.close();
            if (output != null)
                output.close();
        }
    }

    /**
     * Decrypts a file
     * Its content will be unciphered by blocks of one byte
     * @param inputFile Path to the file to read
     * @param outputFile Path to the file to write
     */
    public void decryptFile(File inputFile, File outputFile) throws IOException {
        FileInputStream input = null;
        FileOutputStream output = null;

        try {
            input = new FileInputStream(inputFile);
            output = new FileOutputStream(outputFile);

            int c;
            while ((c = input.read()) != -1) {
                byte decrypted = this.decrypt((byte)c);
                output.write(decrypted);
                //System.out.print((char)decrypted);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            if (input != null)
                input.close();
            if (output != null)
                output.close();
        }
    }

    public String toString() {
        StringBuilder mkey = new StringBuilder();

        for (boolean bit : this.master_key)
            mkey.append(bit ? "1" : "0");

        return "Key : " + mkey.toString();
    }
}
