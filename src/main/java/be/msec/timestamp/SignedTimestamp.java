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

    public SignedTimestamp( byte[] timestamp, byte[] signature )
    {
        this.timestamp = timestamp;
        this.signature = signature;
    }

    public SignedTimestamp( byte[] timestamp, Signature s ) throws SignatureException
    {
        this.timestamp = timestamp;
        s.update( timestamp );
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
