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
    private byte[] validationTime;
    private byte[] validationSignature;

    public SignedTimestamp( byte[] timestamp, byte[] signature, byte[] validationTime, byte[] validationSignature )
    {
        this.timestamp = timestamp;
        this.signature = signature;
        this.validationTime = validationTime;
        this.validationSignature = validationSignature;
    }

    public SignedTimestamp( byte[] timestamp, Signature s, byte[] validationTime ) throws SignatureException
    {
        this.timestamp = timestamp;
        s.update( timestamp );
        this.signature = s.sign();
        this.validationTime = validationTime;
        s.update( validationTime );
        this.validationSignature = s.sign();
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

    public byte[] getValidationTime()
    {
        return validationTime;
    }

    public byte[] getValidationSignature()
    {
        return validationSignature;
    }

    @Override
    public String toString()
    {
        return "SignedTimestamp{" +
                "timestamp=" + Arrays.toString( timestamp ) +
                '}';
    }
}
