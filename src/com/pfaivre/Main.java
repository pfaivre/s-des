/*
 * SDES
 * Pierre Faivre
 *
 * Main.java
 * Creation : 30/03/2016
 * Last modification : 19/09/2016
 */

package com.pfaivre;

import java.io.File;
import java.io.IOException;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import com.pfaivre.crypto.SDES;

public class Main {

    @Option(name="-e", aliases={"--encrypt"}, usage="encrypt a plain file", forbids={"-d"})
    private boolean encrypt = true;

    @Option(name="-d", aliases={"--decrypt"}, usage="decrypt a crypted file", forbids={"-e"})
    private boolean decrypt = false;

    @Option(name="-i", aliases={"--input"}, usage="input file", metaVar="FILE", required=true)
    private String inputFile = null;

    @Option(name="-k", aliases={"--key"}, usage="10-bit key (e.g. 0100101100)", metaVar="KEY", required=true)
    private String key = null;

    @Option(name="-v", usage="verbose mode. prints more details")
    private boolean verbose = false;

    public static void main(String[] args) throws IOException {
        new Main().doMain(args);
    }

    private void doMain(String[] args) throws IOException {
        CmdLineParser parser = new CmdLineParser(this);

        try {
            // parse the arguments.
            parser.parseArgument(args);
        } catch( CmdLineException e ) {
            System.err.println(e.getMessage());
            // print the list of available options
            parser.printUsage(System.err);
            System.err.println();
            System.exit(1);
        }

        boolean error = false;

        File iFile = new File(this.inputFile);

        if (!iFile.exists()) {
            System.err.println(String.format("Unable to find the file %s.", this.inputFile));
            error = true;
        }
        if (iFile.isDirectory()) {
            System.err.println("Please provide a single file. This program cannot process whole directories");
            error = true;
        }

        if (this.key.length() != 10) {
            System.err.println("The key must be of the size of 10 bits");
            error = true;
        }
        else {
            for (char c : this.key.toCharArray()) {
                if (c != '0' && c != '1') {
                    System.err.println("The key must composed of bits (0 or 1)");
                    error = true;
                }
            }
        }

        if (error)
            System.exit(1);

        String[] tokens = this.inputFile.split("\\.(?=[^\\.]+$)");
        String operation = this.decrypt ? "dec" : "enc";
        File oFile = new File(String.format("%s.%s.%s", tokens[0], operation, tokens[1]));

        if (verbose) {
            System.out.println(String.format("Input file: %s", iFile.getPath()));
            System.out.println(String.format("Key: %s", this.key));
        }

        SDES sdes = new SDES(this.key);
        if (this.decrypt) {
            if (verbose)
                System.out.println(String.format("Decripting the file into %s", oFile.getPath()));
            sdes.decryptFile(iFile, oFile);
        }
        else {
            if (verbose)
                System.out.println(String.format("Encrypting the file into %s", oFile.getPath()));
            sdes.encryptFile(iFile, oFile);
        }

        if (verbose) {
            System.out.println("Finished.");
        }
    }
}
