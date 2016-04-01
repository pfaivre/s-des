/**
 * SDES
 * Pierre Faivre
 *
 * Program.java
 * Creation : 30/03/2016
 * Last modification : 01/04/2016
 *
 * Description : Workshop Cryptographie
 * Exia A4 2015/2016
 */

package com.pfaivre;

import com.pfaivre.crypto.SDES;

import java.io.File;
import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {
        File inputFile = new File("/home/pierre/Hubic/EXIA/6 - Cryptographie/Prosit 2/message_test.txt");
        File outputFile = new File("/home/pierre/Hubic/EXIA/6 - Cryptographie/Prosit 2/message_test_enc.txt");

        SDES sdes = new SDES("1100100000");

        sdes.encryptFile(inputFile, outputFile);

        inputFile = new File("/home/pierre/Hubic/EXIA/6 - Cryptographie/Prosit 2/message_test_enc.txt");
        outputFile = new File("/home/pierre/Hubic/EXIA/6 - Cryptographie/Prosit 2/message_test_dec.txt");

        sdes.decryptFile(inputFile, outputFile);
    }
}
