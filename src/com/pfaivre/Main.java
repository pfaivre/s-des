/**
 * SDES
 * Pierre Faivre
 *
 * Program.java
 * Creation : 30/03/2016
 * Last modification : 30/03/2016
 *
 * Description : Workshop Cryptographie
 * Exia A4 2015/2016
 */

package com.pfaivre;

import com.pfaivre.crypto.SDES;

public class Main {

    public static void main(String[] args) {
        try {
            SDES sdes = new SDES("1100100000");
            System.out.println(sdes);
        }
        catch(Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }
}
