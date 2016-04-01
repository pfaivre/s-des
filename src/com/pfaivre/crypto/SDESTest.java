package com.pfaivre.crypto;

import org.junit.Test;

import java.util.ArrayList;

import static org.junit.Assert.*;

/**
 * Created by pierre on 30/03/16.
 */
public class SDESTest {
    @org.junit.Test
    public void p10() {
        System.out.print("Testing p10...");

        // 1001001100
        boolean[] input = new boolean[] {true, false, false, true, false, false, true, true, false, false};

        // 0001101010
        boolean[] expectedOutput = new boolean[] {false, false, false, true, true, false, true, false, true, false};
        boolean[] output = SDES.p10(input);
        assertArrayEquals(expectedOutput, output);

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
        assertArrayEquals(expectedOutput, output);

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
        assertArrayEquals(expectedOutput, output);

        // 0010000011
        boolean[] expectedOutput2 = new boolean[] {false, false, true, false, false, false, false, false, true, true};
        boolean[] output2 = SDES.circularLeftShift(input, 3);
        assertArrayEquals(expectedOutput2, output2);

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

        assertArrayEquals(expectedK1, K1);
        assertArrayEquals(expectedK2, K2);

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
        assertArrayEquals(expectedOutput, output);

        // 10110100
        boolean[] input2 = new boolean[] {true, false, true, true, false, true, false, false};
        // 01111000
        boolean[] expectedOutput2 = new boolean[] {false, true, true, true, true, false, false, false};
        boolean[] output2 = SDES.ip(input2);
        assertArrayEquals(expectedOutput2, output2);

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
        assertArrayEquals(expectedOutput, output);

        // 01111000
        boolean[] input2 = new boolean[] {false, true, true, true, true, false, false, false};
        // 10110100
        boolean[] expectedOutput2 = new boolean[] {true, false, true, true, false, true, false, false};
        boolean[] output2 = SDES.rip(input2);
        assertArrayEquals(expectedOutput2, output2);

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
        assertArrayEquals(expectedOutput, output);

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
        assertArrayEquals(expectedOutput, output);

        System.out.println(" success");
    }

    @org.junit.Test
    public void sboxTransform() {
        System.out.print("Testing sboxTransform...");

        // 01100111
        boolean[] input = new boolean[] {false, true, true, false, false, true, true, true};
        // 1011
        boolean[] expectedOutput = new boolean[] {true, false, true, true};
        boolean[] output = SDES.sboxTransform(input);
        assertArrayEquals(expectedOutput, output);

        System.out.println(" success");
    }

    @org.junit.Test
    public void p4() {
        System.out.print("Testing p4...");

        // 1011
        boolean[] input = new boolean[] {true, false, true, true};
        // 0111
        boolean[] expectedOutput = new boolean[] {false, true, true, true};
        boolean[] output = SDES.p4(input);
        assertArrayEquals(expectedOutput, output);

        // 0110
        boolean[] input2 = new boolean[] {false, true, true, false};
        // 1010
        boolean[] expectedOutput2 = new boolean[] {true, false, true, false};
        boolean[] output2 = SDES.p4(input2);
        assertArrayEquals(expectedOutput2, output2);

        System.out.println(" success");
    }

    @org.junit.Test
    public void sw() {
        System.out.print("Testing sw...");

        // 11110000
        boolean[] input = new boolean[] {true, true, true, true, false, false, false, false};
        // 00001111
        boolean[] expectedOutput = new boolean[] {false, false, false, false, true, true, true, true};
        boolean[] output = SDES.sw(input);
        assertArrayEquals(expectedOutput, output);

        // 10010011
        boolean[] input2 = new boolean[] {true, false, false, true, false, false, true, true};
        // 00111001
        boolean[] expectedOutput2 = new boolean[] {false, false, true, true, true, false, false, true};
        boolean[] output2 = SDES.sw(input2);
        assertArrayEquals(expectedOutput2, output2);

        System.out.println(" success");
    }

    @org.junit.Test
    public void byte2bool() {
        System.out.print("Testing byte2bool...");

        // 01000011 ('C')
        byte input = (byte)0b01000011;
        // 01000011
        boolean[] expectedOutput = new boolean[] {false, true, false, false, false, false, true, true};
        boolean[] output = SDES.byte2bool(input);
        assertArrayEquals(expectedOutput, output);

        // 11001010 ('Ê')
        byte input2 = (byte)0b11001010;
        // 11001010
        boolean[] expectedOutput2 = new boolean[] {true, true, false, false, true, false, true, false};
        boolean[] output2 = SDES.byte2bool(input2);
        assertArrayEquals(expectedOutput2, output2);

        System.out.println(" success");
    }

    @org.junit.Test
    public void bool2byte() {
        System.out.print("Testing bool2byte...");

        // 01000011
        boolean[] input = new boolean[] {false, true, false, false, false, false, true, true};
        // 01000011 ('C')
        byte expectedOutput = (byte)0b01000011;
        byte output = SDES.bool2byte(input);
        assertEquals(expectedOutput, output);

        // 11001010
        boolean[] input2 = new boolean[] {true, true, false, false, true, false, true, false};
        // 11001010 ('Ê')
        byte expectedOutput2 = (byte)0b11001010;
        byte output2 = SDES.bool2byte(input2);
        assertEquals(expectedOutput2, output2);

        System.out.println(" success");
    }

    @org.junit.Test
    public void encrypt() {
        System.out.print("Testing encrypt...");

        // 11010101
        byte input = (byte)0b11010101;
        // 01110011
        byte expectedOutput = (byte)0b01110011;
        SDES sdes = new SDES("0111010001");
        byte output = sdes.encrypt(input);
        assertEquals(expectedOutput, output);

        // 01001100
        byte input2 = (byte)0b01001100;
        // 00100010
        byte expectedOutput2 = (byte)0b00100010;
        SDES sdes2 = new SDES("1111111111");
        byte output2 = sdes2.encrypt(input2);
        assertEquals(expectedOutput2, output2);

        // 00000000
        byte input3 = (byte)0b00000000;
        // 11110000
        byte expectedOutput3 = (byte)0b11110000;
        SDES sdes3 = new SDES("0000000000");
        byte output3 = sdes3.encrypt(input3);
        assertEquals(expectedOutput3, output3);

        // 11111111
        byte input4 = (byte)0b11111111;
        // 00001111
        byte expectedOutput4 = (byte)0b00001111;
        SDES sdes4 = new SDES("1111111111");
        byte output4 = sdes4.encrypt(input4);
        assertEquals(expectedOutput4, output4);

        System.out.println(" success");
    }

    @org.junit.Test
    public void decrypt() {
        System.out.print("Testing decrypt...");

        // 01110011
        byte input = (byte)0b01110011;
        // 11010101
        byte expectedOutput = (byte)0b11010101;
        SDES sdes = new SDES("0111010001");
        byte output = sdes.decrypt(input);
        assertEquals(expectedOutput, output);

        // 00100010
        byte input2 = (byte)0b00100010;
        // 01001100
        byte expectedOutput2 = (byte)0b01001100;
        SDES sdes2 = new SDES("1111111111");
        byte output2 = sdes2.decrypt(input2);
        assertEquals(expectedOutput2, output2);

        // 11110000
        byte input3 = (byte)0b11110000;
        // 00000000
        byte expectedOutput3 = (byte)0b00000000;
        SDES sdes3 = new SDES("0000000000");
        byte output3 = sdes3.decrypt(input3);
        assertEquals(expectedOutput3, output3);

        // 00001111
        byte input4 = (byte)0b00001111;
        // 11111111
        byte expectedOutput4 = (byte)0b11111111;
        SDES sdes4 = new SDES("1111111111");
        byte output4 = sdes4.decrypt(input4);
        assertEquals(expectedOutput4, output4);

        System.out.println(" success");
    }
}
