package be.msec.timestamp;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.Signature;
import java.security.SignatureException;

/**
 * @author Pieter
 * @version 1.0
 */
public class SignedTimestamp implements Serializable
{
    private long   timestamp;
    private byte[] signature;

    public SignedTimestamp( long timestamp, byte[] signature )
    {
        this.timestamp = timestamp;
        this.signature = signature;
    }

    public SignedTimestamp( Long timestamp, Signature s ) throws SignatureException
    {
        this.timestamp = timestamp;
        s.update( ByteBuffer.allocate( Long.SIZE / Byte.SIZE ).putLong( timestamp ).array() );
        this.signature = s.sign();
    }

    public boolean validate( Signature s ) throws SignatureException
    {
        s.update( ByteBuffer.allocate( Long.SIZE / Byte.SIZE ).putLong( timestamp ).array() );
        return s.verify( signature );
    }

    public long getTimestamp()
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
                "timestamp=" + timestamp +
                '}';
    }
}
