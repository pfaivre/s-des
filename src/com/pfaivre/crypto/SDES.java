/*
 * SDES
 * Pierre Faivre
 *
 * SDES.java
 * Creation : 30/03/2016
 * Last modification : 01/04/2016
 */

package com.pfaivre.crypto;

import java.io.*;
import java.util.ArrayList;

/**
 * Implémentation de l'algorithme S-DES
 * Cette classe permet le chiffrement ainsi que le déchiffrement d'un message.
 * // TODO: Translate all the comments in english
 */
public class SDES {
    /**
     * Clé de chiffrement
     */
    private boolean[] master_key;

    /**
     * Sous-clé 1
     */
    private boolean[] K1;

    /**
     * Sous-clé 2
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
     * Instancie une nouvelle instance de chiffrment S-DES
     * @param key Clé de chiffrement de 10 bits. Exemple "0110100111"
     */
    public SDES(String key) {
        master_key = new boolean[10];

//        if (key.length() != 10)
//            throw new Exception("La clé doit faire 10 bits.");

        for (int i = 0 ; i < key.length() ; i++) {
            if (key.charAt(i) == '0')
                this.master_key[i] = false;
            else if (key.charAt(i) == '1')
                this.master_key[i] = true;
//            else
//                throw new Exception("La clé ne doit contenir que des '0' ou des '1'.");
        }

        ArrayList<boolean[]> keys = SDES.generateKeys(this.master_key);
        this.K1 = keys.get(0);
        this.K2 = keys.get(1);
    }

    // #################################
    // Génération des sous-clés K1 et K2
    // #################################

    /**
     * Effectue une permutation P10
     * P10(k1, k2, k3, k4, k5, k6, k7, k8, k9, k10) = (k3, k5, k2, k7, k4, k10, k1, k9, k8, k6)
     * @param input Clé d'entrée de 10 bits à transformer
     * @return un tableau de 8 booléens.
     */
    static boolean[] p10(boolean[] input) {
        boolean[] output = new boolean[10];

        // C'est une permutation arbitraire, il faut donc le faire à la main
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
     * Effectue une permutation P8
     * P10(k1, k2, k3, k4, k5, k6, k7, k8, k9, k10) = (k6, k3, k7, k4, k8, k5, k10, k9)
     * @param input Clé d'entrée de 10 bits à transformer
     * @return un tableau de 8 booléens.
     */
    static boolean[] p8(boolean[] input) {
        boolean[] output = new boolean[8];

        // C'est une permutation arbitraire, il faut donc la faire à la main
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
     * Effectue un décalage de bits vers la gauche sur chaque moitié de 5 bits
     * Exemple : 10000 01100 devient 00001 11000 avec un décalage de 1 bit.
     * @param input Suite de 10 bits à transformer
     * @param offset Amplitude du décalage
     */
    static boolean[] circularLeftShift(boolean[] input, int offset) {
        // Découpage en deux moitiés de 5 bits.
        boolean[] leftHalf = new boolean[5];
        boolean[] rightHalf = new boolean[5];

        // Décalage vers la gauche
        for (int i = 0 ; i < 5 ; i++) {
            leftHalf[5 - (((5 - i - 1) + offset) % 5) - 1] = input[i];
            rightHalf[5 - (((5 - i - 1) + offset) % 5) - 1] = input[i + 5];
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
     * @param input Octet à permuter
     * @return Octet transformé
     */
    static boolean[] ip(boolean[] input) {
        boolean[] output = new boolean[8];

        // C'est une permutation arbitraire, il faut donc la faire à la main
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
     * Effectue une permutation initiale inverse (Reversed Initial Permutation, RIP ou IP-1) sur un octet
     * IP−1(k1, k2, k3, k4, k5, k6, k7, k8) = (k4, k1, k3, k5, k7, k2, k8, k6)
     * @param input Octet à permuter
     * @return Octet transformé
     */
    static boolean[] rip(boolean[] input) {
        boolean[] output = new boolean[8];

        // C'est une permutation arbitraire, il faut donc la faire à la main
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
     * Les deux opérandes doivent avoir le même nombre de bits
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

    /**
     * Transforme un octet en utilisant les S-Boxes comme table de correspondance
     * @param input Une suite de 8 bits
     * @return Une suite de 4 bits résultant de la transformation
     */
    static boolean[] sboxTransform(boolean[] input) {
        int i, j = 0;

        // Moitié gauche avec S0

        // Les 1er et 4eme bits donnent l'indice de la ligne
        i = (input[0] ? 2 : 0) + (input[3] ? 1 : 0);
        // Les 2eme et 3eme bits donnent l'indice de la colonne
        j = (input[1] ? 2 : 0) + (input[2] ? 1 : 0);

        // Ces indices pointent vers une case de S0 dont on récupère la valeur
        boolean[] s0Result = S0[i][j];

        // Moitié droite avec S1

        // Les 1er et 4eme bits donnent l'indice de la ligne
        i = (input[4] ? 2 : 0) + (input[7] ? 1 : 0);
        // Les 2eme et 3eme bits donnent l'indice de la colonne
        j = (input[5] ? 2 : 0) + (input[6] ? 1 : 0);

        // Ces indices pointent vers une case de S1 dont on récupère la valeur
        boolean[] s1Result = S1[i][j];

        // Enfin on rassemble les résultats obtenus en une suite de 4 bits
        return new boolean[] {s0Result[0], s0Result[1], s1Result[0], s1Result[1]};
    }

    /**
     * Effectue une permutation P4
     * P4(k1, k2, k3, k4) = (k2, k4, k3, k1)
     * @param input Suite de 4 bits à transformer
     * @return Suite de 4 bit après transformation
     */
    static boolean[] p4(boolean[] input) {
        boolean[] output = new boolean[4];

        // C'est une permutation arbitraire, il faut donc la faire à la main
        output[0] = input[1];
        output[1] = input[3];
        output[2] = input[2];
        output[3] = input[0];

        return output;
    }

    /**
     * Sous-fonction de transformation de chiffrement
     * @param right Moitié droite de l'octet à transformer
     * @param sk Sous-clé K1 ou K2
     * @return un ensemble de 4 bits
     */
    static boolean[] f(boolean[] right, boolean[] sk) {
        // on applique E/P sur right
        // on effectue un OU exclusif entre le résultat obtenu et la sous-clé sk passée en paramètre
        // on effectue les opération s des sand-boxes sur chaque moitié obtenue
        // on applique P4 sur le résultat et on le renvoie
        return p4(sboxTransform(xor(ep(right), sk)));
    }

    /**
     * Transformation fK
     * @param bits Suite de 8 bits issus de IP ou RIP
     * @param sk Sous-clé K1 ou K2
     * @return une suite de 8 bits
     */
    static boolean[] fK(boolean[] bits, boolean[] sk) {
        // on effectue un OU exclusif entre les 4 bits de gauche en entrée et
        // le résultat de la fonction F appliqué e aux 4 bits de droite en
        // entrée et a la clé passée en paramètre.
        // On concatène les 4 bits de droite en entrée avec le résu ltat
        // précédemmen t obtenu, et on renvoie.

        // Découpage en deux moitiés de 4 bits.
        boolean[] left = new boolean[4];
        boolean[] right = new boolean[4];
        System.arraycopy(bits, 0, left, 0, left.length);
        System.arraycopy(bits, 4, right, 0, right.length);

        // = left XOR f(right, SK)
        boolean[] transformed = xor(left, f(right, sk));

        // Concat(transformed, right)
        boolean[] output = new boolean[8];
        System.arraycopy(transformed, 0, output, 0, transformed.length);
        System.arraycopy(right, 0, output, 4, right.length);

        return output;
    }

    /**
     * Échange les deux moitiés de 4 bits d'un octet
     * Par exemple, 11110000 devient 00001111
     * @param input Octet à transformer
     * @return Octet résultant de la transformation
     */
    static boolean[] sw(boolean[] input) {
        // Création d'un nouvel octet en intervertant les deux moitiés
        boolean[] output = new boolean[8];
        System.arraycopy(input, 4, output, 0, 4);
        System.arraycopy(input, 0, output, 4, 4);

        return output;
    }

    /**
     * Convertit un char (un octet du coup) en tableau de booléens
     * @param block Octet à traduire
     * @return Tableau de 8 boolean
     */
    static boolean[] byte2bool(byte block) {
        boolean[] result = new boolean[8];

        // On parcourt l'octet bit par bit
        for (int i = 0 ; i < 8 ; i++) {
            // Permet de "découper" le bit à la position i dans l'octet
            int b = ((block >> i) & 1);

            // Et on l'insère dans le tableau de boolean
            result[7 - i] = b == 1;
        }

        return result;
    }

    /**
     * Convertit un tableau de booléens en char (un octet quoi)
     * @param block Tableau de 8 booléens représentants les bits
     * @return char
     */
    static byte bool2byte(boolean[] block) {
        byte result = 0b00000000;

        // Pour chaque booléen (bit) du tableau
        for (int i = 0 ; i < block.length ; i++) {
            // On "l'imprime" à droite dans le char
            result = (byte)(result | (block[i] ? 1 : 0));

            // Et on décale les précédents vers la gauche pour laisser la place au suivant
            if (i < block.length - 1)
                result = (byte)(result << 1);
        }

        return result;
    }

    /**
     * Chiffre un block de données
     * @param block Un octet de données à chiffrer
     * @return Un octet chiffré
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
     * Déchiffre un block de données
     * @param block Un octer à déchiffrer
     * @return Un octet en clair
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
     * Chiffre un fichier
     * Le contenu du fichier sera chiffré octet par octet
     * @param inputFile Chemin vers le fichier à lire
     * @param outputFile Chemin vers le fichier à écrire
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
     * Déchiffre un fichier
     * Le contenu du fichier sera déchiffré octet par octet
     * @param inputFile Chemin vers le fichier à lire
     * @param outputFile Chemin vers le fichier à écrire
     */
    public void decryptFile(File inputFile, File outputFile) throws IOException {
        FileInputStream input = null;
        FileOutputStream output = null;

        try {
            input = new FileInputStream(inputFile);
            output = new FileOutputStream(outputFile);

            int c = -1;
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

        return "Clé : " + mkey.toString();
    }
}
