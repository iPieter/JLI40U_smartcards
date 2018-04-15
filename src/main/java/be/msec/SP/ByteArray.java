package be.msec.SP;

import java.io.Serializable;

/**
 * This (useless?( class is needed because we use an object steam and this
 * was easier than mixing it with a byte stream.
 *
 * @author Pieter
 * @version 1.0
 */
public class ByteArray implements Serializable
{
    private byte[] challenge;

    public ByteArray( byte[] challenge )
    {
        this.challenge = challenge;
    }

    public byte[] getChallenge()
    {
        return challenge;
    }

    public void setChallenge( byte[] challenge )
    {
        this.challenge = challenge;
    }
}


