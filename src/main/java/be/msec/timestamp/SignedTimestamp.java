package be.msec.timestamp;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * @author Pieter
 * @version 1.0
 */
public class SignedTimestamp implements Serializable
{
    private byte[] timestamp;
    private byte[] signature;

    public SignedTimestamp( long now, long nowDelta, Signature s ) throws SignatureException
    {
        this.timestamp = new byte[16];

        byte [] nowBytes = ByteBuffer.allocate( Long.SIZE / Byte.SIZE ).putLong( now ).array();
        byte [] deltaBytes = ByteBuffer.allocate( Long.SIZE / Byte.SIZE ).putLong( nowDelta ).array();

        for( int i = 0; i < nowBytes.length; i++ )
            timestamp[i] = nowBytes[i];

        for( int i = 0; i < deltaBytes.length; i++ )
            timestamp[i + nowBytes.length ] = deltaBytes[i];

        s.update( this.timestamp );

        this.signature = s.sign();
    }


    public boolean validate( Signature s ) throws SignatureException
    {
        s.update( timestamp );
        return s.verify( signature );
    }

    public byte[] getTimestamp()
    {
        return timestamp;
    }

    public byte[] getSignature()
    {
        return signature;
    }

    @Override
    public String toString()
    {
        return "SignedTimestamp{" +
                "timestamp=" + Arrays.toString( timestamp ) +
                '}';
    }
}
