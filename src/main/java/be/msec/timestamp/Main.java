package be.msec.timestamp;

import java.nio.ByteBuffer;

/**
 * @author Pieter
 * @version 1.0
 */
public class Main
{
    public static void main( String[] args )
    {
        long test = 128L;

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(test);


        System.out.println(   buffer.array());

        System.out.println("test");
    }
}
