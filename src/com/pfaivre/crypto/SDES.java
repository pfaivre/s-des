/**
 * SDES
 * Pierre Faivre
 *
 * SDES.java
 * Creation : 30/03/2016
 * Last modification : 30/03/2016
 *
 * Description : Workshop Cryptographie
 * Exia A4 2015/2016
 */

package com.pfaivre.crypto;

import java.util.ArrayList;

/**
 * Implémentation de l'algorithme S-DES
 * Cette classe permet le chiffrement ainsi que le déchiffrement d'un message.
 */
public class SDES {
    /**
     * Clé de chiffrement
     */
    private boolean[] master_key;

    private boolean[][][] s_box1 = new boolean[4][4][2];
    private boolean[][][] s_box2 = new boolean[4][4][2];

    public SDES(String key) throws Exception {
        master_key = new boolean[10];

        if (key.length() != 10)
            throw new Exception("La clé doit faire 10 bits.");

        for (int i = 0 ; i < key.length() ; i++) {
            if (key.charAt(i) == '0')
                this.master_key[i] = false;
            else if (key.charAt(i) == '1')
                this.master_key[i] = true;
            else
                throw new Exception("La clé ne doit contenir que des '0' ou des '1'.");
        }
    }

    // #################################
    // Génération des sous-clés K1 et K2
    // #################################

    /**
     * Effectue une permutation P10
     * P10(k1, k2, k3, k4, k5, k6, k7, k8, k9, k10) = (k3, k5, k2, k7, k4, k10, k1, k9, k8, k6)
     * @param key Clé d'entrée de 10 bits à transformer
     * @return un tableau de 8 booléens.
     */
    static boolean[] p10(boolean[] key) {
        boolean[] output = new boolean[10];

        // C'est une permutation arbitraire, il faut donc le faire à la main
        output[0] = key[2];
        output[1] = key[4];
        output[2] = key[1];
        output[3] = key[6];
        output[4] = key[3];
        output[5] = key[9];
        output[6] = key[0];
        output[7] = key[8];
        output[8] = key[7];
        output[9] = key[5];

        return output;
    }

    /**
     * Effectue une permutation P8
     * P10(k1, k2, k3, k4, k5, k6, k7, k8, k9, k10) = (k6, k3, k7, k4, k8, k5, k10, k9)
     * @param key Clé d'entrée de 10 bits à transformer
     * @return un tableau de 8 booléens.
     */
    static boolean[] p8(boolean[] key) {
        boolean[] output = new boolean[8];

        // C'est une permutation arbitraire, il faut donc la faire à la main
        output[0] = key[5];
        output[1] = key[2];
        output[2] = key[6];
        output[3] = key[3];
        output[4] = key[7];
        output[5] = key[4];
        output[6] = key[9];
        output[7] = key[8];

        return output;
    }

    /**
     * Effectue un décalage de bits vers la gauche sur chaque moitié de 5 bits
     * Exemple : 10000 01100 devient 00001 11000 avec un décalage de 1 bit.
     * @param key Clé d'entrée de 10 bits à transformer
     * @param bits Amplitude du décalage
     */
    static boolean[] circularLeftShift(boolean[] key, int bits) {
        // Découpage en deux moitiés de 5 bits.
        boolean[] leftHalf = new boolean[5];
        System.arraycopy(key, 0, leftHalf, 0, leftHalf.length);
        boolean[] rightHalf = new boolean[5];
        System.arraycopy(key, 5, rightHalf, 0, rightHalf.length);

        // Décalage de chaque moitié (peut être optimisé)
        for (int i = 0 ; i < bits ; i++) {
            boolean ltmp = leftHalf[0];
            boolean rtmp = rightHalf[0];

            for (int j = 0; j < 4; j++) {
                leftHalf[j] = leftHalf[j + 1];
                rightHalf[j] = rightHalf[j + 1];
            }

            leftHalf[4] = ltmp;
            rightHalf[4] = rtmp;
        }

        // Rassemblement des deux moitiés
        boolean[] output = new boolean[10];
        System.arraycopy(leftHalf, 0, output, 0, leftHalf.length);
        System.arraycopy(rightHalf, 0, output, 5, rightHalf.length);

        return output;
    }

    /**
     * Génère les deux sous-clés à partir de la clé principale
     * @param master_key Clé principale de 10 bits
     * @return ArrayList contenant dans la case 0 => K1 et dans la case 1 => K2
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

    // ########################
    // Fonctions de chiffrement
    // ########################

    /**
     * Effectue une permutation initiale (Initial Permutation, IP) sur un octet
     * IP(k1, k2, k3, k4, k5, k6, k7, k8) = (k2, k6, k3, k1, k4, k8, k5, k7)
     * @param plainText Octet à permuter
     * @return Octet transformé
     */
    static boolean[] ip(boolean[] plainText) {
        boolean[] output = new boolean[8];

        // C'est une permutation arbitraire, il faut donc la faire à la main
        output[0] = plainText[1];
        output[1] = plainText[5];
        output[2] = plainText[2];
        output[3] = plainText[0];
        output[4] = plainText[3];
        output[5] = plainText[7];
        output[6] = plainText[4];
        output[7] = plainText[6];

        return output;
    }

    /**
     * Effectue une permutation initiale inverse (Reversed Initial Permutation, RIP ou IP-1) sur un octet
     * IP−1(k1, k2, k3, k4, k5, k6, k7, k8) = (k4, k1, k3, k5, k7, k2, k8, k6)
     * @param permutedText Octet à permuter
     * @return Octet transformé
     */
    static boolean[] rip(boolean[] permutedText) {
        boolean[] output = new boolean[8];

        // C'est une permutation arbitraire, il faut donc la faire à la main
        output[0] = permutedText[3];
        output[1] = permutedText[0];
        output[2] = permutedText[2];
        output[3] = permutedText[4];
        output[4] = permutedText[6];
        output[5] = permutedText[1];
        output[6] = permutedText[7];
        output[7] = permutedText[5];

        return output;
    }

    /**
     * Effectue une opération d'expansion/permutation (E/P) sur un groupe de 4 bits.
     * E/P(n1, n2, n3, n4) = (n4, n1, n2, n3, n2, n3, n4, n1)
     * @param input Groupe de 4 bits à transformer
     * @return Octet résultant de la transformation
     */
    static boolean[] ep(boolean[] input) {
        boolean[] output = new boolean[8];

        // C'est une permutation arbitraire, il faut donc la faire à la main
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
     * Effectue une opération de ou exclusif (XOR) sur deux suites de bits
     * Les deux opérandes doivent avoir le même nombre de bits.
     * @param a Opérande 1
     * @param b Opérande 2
     * @return Résultat
     */
    static boolean[] xor(boolean[] a, boolean[] b) {
        boolean[] output = new boolean[a.length];

        for (int i = 0 ; i < a.length ; i++)
            output[i] = a[i] ^ b[i];

        return output;
    }

    public String toString() {
        StringBuilder mkey = new StringBuilder();

        for (boolean bit : this.master_key)
            mkey.append(bit ? "1" : "0");

        return "Clé : " + mkey.toString();
    }
}
