package be.msec.timestamp;

import java.io.Serializable;
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

    public SignedTimestamp( byte[] timestamp, byte[] validationTime )
    {
        this.timestamp = new byte[timestamp.length + validationTime.length];

        for (int i = 0; i < timestamp.length; i++)
            this.timestamp[i] = timestamp[i];

        for (int i = 0; i < validationTime.length; i++)
            this.timestamp[timestamp.length + i] = validationTime[i];

    }

    public SignedTimestamp( byte[] timestamp, Signature s, byte[] validationTime ) throws SignatureException
    {
        this(timestamp, validationTime);

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
