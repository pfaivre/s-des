package com.pfaivre.crypto;

import org.junit.Test;

import java.util.ArrayList;

import static org.junit.Assert.*;

/**
 * Created by pierre on 30/03/16.
 */
public class SDESTest {
    @org.junit.Before
    public void setUp() throws Exception {

    }

    @org.junit.After
    public void tearDown() throws Exception {

    }

    @org.junit.Test
    public void p10() {
        System.out.print("Testing p10...");

        // 1001001100
        boolean[] input = new boolean[] {true, false, false, true, false, false, true, true, false, false};

        // 0001101010
        boolean[] expectedOutput = new boolean[] {false, false, false, true, true, false, true, false, true, false};
        boolean[] output = SDES.p10(input);
        assertArrayEquals(output, expectedOutput);

        System.out.println(" success");
    }

    @org.junit.Test
    public void p8() {
        System.out.print("Testing p8...");

        // 1001001100
        boolean[] input = new boolean[] {true, false, false, true, false, false, true, true, false, false};

        // 00111000
        boolean[] expectedOutput = new boolean[] {false, false, true, true, true, false, false, false};
        boolean[] output = SDES.p8(input);
        assertArrayEquals(output, expectedOutput);

        System.out.println(" success");
    }

    @org.junit.Test
    public void circularLeftShift() {
        System.out.print("Testing circularLeftShift...");

        // 1000001100
        boolean[] input = new boolean[] {true, false, false, false, false, false, true, true, false, false};

        // 0000111000
        boolean[] expectedOutput = new boolean[] {false, false, false, false, true, true, true, false, false, false};
        boolean[] output = SDES.circularLeftShift(input, 1);
        assertArrayEquals(output, expectedOutput);

        // 0010000011
        boolean[] expectedOutput2 = new boolean[] {false, false, true, false, false, false, false, false, true, true};
        boolean[] output2 = SDES.circularLeftShift(input, 3);
        assertArrayEquals(output2, expectedOutput2);

        System.out.println(" success");
    }

    @org.junit.Test
    public void generateKeys() {
        System.out.print("Testing generateKeys...");

        // 1010000010
        boolean[] input = new boolean[] {true, false, true, false, false, false, false, false, true, false};

        // 10100100
        boolean[] expectedK1 = new boolean[] {true, false, true, false, false, true, false, false};
        // 01000011
        boolean[] expectedK2 = new boolean[] {false, true, false, false, false, false, true, true};

        ArrayList<boolean[]> keys = SDES.generateKeys(input);

        boolean[] K1 = keys.get(0);
        boolean[] K2 = keys.get(1);

        assertArrayEquals(K1, expectedK1);
        assertArrayEquals(K2, expectedK2);

        System.out.println(" success");
    }

    @org.junit.Test
    public void ip() {
        System.out.print("Testing ip...");

        // 01110010
        boolean[] input = new boolean[] {false, true, true, true, false, false, true, false};
        // 10101001
        boolean[] expectedOutput = new boolean[] {true, false, true, false, true, false, false, true};
        boolean[] output = SDES.ip(input);
        assertArrayEquals(output, expectedOutput);

        // 10110100
        boolean[] input2 = new boolean[] {true, false, true, true, false, true, false, false};
        // 01111000
        boolean[] expectedOutput2 = new boolean[] {false, true, true, true, true, false, false, false};
        boolean[] output2 = SDES.ip(input2);
        assertArrayEquals(output2, expectedOutput2);

        System.out.println(" success");
    }

    @org.junit.Test
    public void rip() {
        System.out.print("Testing rip...");

        // 11101101
        boolean[] input = new boolean[] {true, true, true, false, true, true, false, true};
        // 01110111
        boolean[] expectedOutput = new boolean[] {false, true, true, true, false, true, true, true};
        boolean[] output = SDES.rip(input);
        assertArrayEquals(output, expectedOutput);

        // 01111000
        boolean[] input2 = new boolean[] {false, true, true, true, true, false, false, false};
        // 10110100
        boolean[] expectedOutput2 = new boolean[] {true, false, true, true, false, true, false, false};
        boolean[] output2 = SDES.rip(input2);
        assertArrayEquals(output2, expectedOutput2);

        System.out.println(" success");
    }

    @org.junit.Test
    public void ep() {
        System.out.print("Testing ep...");

        // 1001
        boolean[] input = new boolean[] {true, false, false, true};
        // 11000011
        boolean[] expectedOutput = new boolean[] {true, true, false, false, false, false, true, true};
        boolean[] output = SDES.ep(input);
        assertArrayEquals(output, expectedOutput);

        System.out.println(" success");
    }

    @org.junit.Test
    public void xor() {
        System.out.print("Testing xor...");

        // 10010100
        boolean[] inputA = new boolean[] {true, false, false, true, false, true, false, false};
        // 01101110
        boolean[] inputB = new boolean[] {false, true, true, false, true, true, true, false};
        // 11111010
        boolean[] expectedOutput = new boolean[] {true, true, true, true, true, false, true, false};
        boolean[] output = SDES.xor(inputA, inputB);
        assertArrayEquals(output, expectedOutput);

        System.out.println(" success");
    }
}
