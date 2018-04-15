package be.msec.smartcard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class IdentityCard extends Applet
{
    private final static byte IDENTITY_CARD_CLA = ( byte ) 0x80;

    private static final byte VALIDATE_PIN_INS = 0x22;
    private static final byte GET_SERIAL_INS   = 0x24;

    private static final byte SHOULD_UPDATE_TIME_INS  = 0x26;
    private static final byte UPDATE_TIME_INS  = 0x27;

    private static final byte TEST_SIGNATURE_INS  = 0x28;

    private static final byte CLEAR_INPUT_BUFFER_INS  = 0x30;
    private static final byte UPDATE_INPUT_BUFFER_INS = 0x31;
    private static final byte GET_OUTPUT_BUFFER_INS = 0x32;

    private final static byte PIN_TRY_LIMIT = ( byte ) 0x03;
    private final static byte PIN_SIZE      = ( byte ) 0x04;

    private final static short SW_VERIFICATION_FAILED       = 0x6300;
    private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

    private final static byte AUTHENTICATE_SP_INS   = 0x50;
    private final static byte CONFIRM_CHALLENGE_INS = 0x51;

    private byte[] serial = new byte[]{ 0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05 };
    private OwnerPIN pin;

    /**
     *  TimeStamp:
     * */
    private byte[] currentTime = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    private byte[] validationTime = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    private byte isTimeOK = 0;
    private byte[] timestampExponent = new byte[] {1, 0, 1};
    private byte[] timestampModulus = new byte[] {-123, 6, 30, -1, -126, 77, 91, 95, 17, -14, 8, 127, 76, -55, 120, 114, -72, -55, 73, -49, 112, 125, 105, 28, 87, 90, 13, -57, 75, 87, 18, 86, 74, 65, -96, -89, -93, -80, -53, -28, 93, 30, 71, 32, 14, 124, 110, -55, 107, -47, 26, 15, 54, -61, 125, 114, 14, -11, 122, 63, -55, -64, -128, -54, -32, 119, 73, 48, -83, -123, -9, -85, -3, 5, -8, -6, 123, 102, -121, -120, -1, 107, -23, 85, -64, 78, 50, -38, -107, 100, 89, 60, 41, 13, -91, 27, -4, 29, -58, 125, -37, -30, 94, -70, -8, -60, 32, 72, 1, 69, -1, 70, 24, -11, -98, -74, -33, -97, -115, -66, 92, -100, 108, -97, 93, -98, -47, -120, -25, 57, 0, -1, 118, -62, 56, -94, 69, 107, -46, 85, -87, -121, -51, 48, -75, 53, -66, 73, -37, -14, -87, 78, -107, 120, 114, 18, -120, -18, 94, -79, -77, -24, 12, -128, -56, -15, 67, -11, 15, -18, -1, 51, -1, -98, 101, 113, -49, -6, 77, 117, 120, 52, 89, -32, -8, 108, 29, 72, 111, -96, -9, -78, -4, -72, -10, -65, 114, 65, -121, 118, -1, -39, 3, 15, 79, -25, 69, -90, 15, -99, 81, 43, -89, 80, -87, -69, -49, -83, -46, 21, -23, -121, -53, -84, -118, 121, -60, -19, -87, -89, -126, 115, 43, 121, -88, -18, -100, 68, 50, 43, -69, -124, 107, -40, 91, 125, 64, 87, -95, 58, 41, 22, -16, -103, 57, -55};
    private RSAPublicKey timestampPublicKey;

    /**
     *  CA PK
     * */
    private byte[] caExponent = new byte[] {1, 0, 1};
    private byte[] caModulus = new byte[] {-32, -46, -12, -101, 25, 10, 111, 80, 80, -6, 118, -46, -71, 93, -94, 19, -94, 50, 3, -93, 54, -31, 108, 80, 113, 59, 50, -28, -14, -42, -66, 58, 27, -84, -58, -99, 101, 34, 71, 108, 118, -56, -5, -128, 108, -13, -16, 55, 66, 97, -76, -59, -78, -106, 39, 21, 94, -92, 14, -98, 48, -79, 28, 100, 51, 109, 23, 68, -82, 93, 6, 106, -19, -124, 39, 65, 11, 52, -34, 71, 96, -15, 13, -40, 76, 100, 101, 101, -22, -43, -114, 106, 87, -73, -99, 99, -60, -123, -123, 119, -118, 30, -60, -103, -9, -110, 36, -52, -26, -2, -82, 117, -119, 46, 115, -111, 72, -27, -50, 7, 11, 110, 91, 86, -56, -9, -79, -106, -113, -4, -59, -22, -127, -87, -97, -109, -2, -64, -122, 45, 76, -128, -103, 102, -3, 108, -107, -12, 24, 54, 121, 115, 121, -82, -14, -21, 20, 23, -126, -117, 37, -99, 57, 26, 105, 58, -4, -93, 117, 36, 41, -94, 64, 48, -5, -119, 62, 81, -106, -108, 115, 76, 113, -53, -33, 62, 31, 68, -90, -33, -120, -68, 125, 59, -106, 48, -124, -92, 89, -101, 65, -49, 56, 117, 108, -34, -72, 119, -112, 90, 121, -95, -15, -5, 2, 87, 101, 55, 14, -50, -48, 99, -128, -60, -36, -43, -28, -88, 70, -25, -119, 6, 53, 74, 84, -11, -65, -91, -43, -85, -54, -91, -61, -103, 65, 98, -5, -6, -87, -27, -2, -67, -77, 64, -126, -127};
    private RSAPublicKey caPublicKey;


    /*
    *   Transient IN buffer
    * */
    private short currentInBufferOffset = 0;
    private byte[] transientInBuffer;
    private short MAX_BUFFER_SIZE = 1024;

    /*
     *   Transient OUT buffer
     * */
    private byte[] transientOutBuffer;


    /*
    *   Symmetric communication
    * */
    private AESKey aesKey;
    byte [] challenge;

    private IdentityCard()
    {
        /*
         * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
        pin = new OwnerPIN( PIN_TRY_LIMIT, PIN_SIZE );
        pin.update( new byte[]{ 0x01, 0x02, 0x03, 0x04 }, ( short ) 0, PIN_SIZE );

        timestampPublicKey = (RSAPublicKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PUBLIC, (short)2048, false );
        timestampPublicKey.setExponent( timestampExponent, (short)0, (short) timestampExponent.length );
        timestampPublicKey.setModulus( timestampModulus, (short)0, (short) timestampModulus.length );

        caPublicKey = (RSAPublicKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PUBLIC, (short)2048, false );
        caPublicKey.setExponent( caExponent, (short)0, (short) caExponent.length );
        caPublicKey.setModulus( caModulus, (short)0, (short) caModulus.length );


        transientInBuffer = JCSystem.makeTransientByteArray( MAX_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET );
        transientOutBuffer = JCSystem.makeTransientByteArray( MAX_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET );

        challenge = JCSystem.makeTransientByteArray( (short)16, JCSystem.CLEAR_ON_RESET );

        for( short i = 0; i < (short)16; i++ )
            challenge[i] = (byte)i;

		/*
		 * This method registers the applet with the JCRE on the card.
		 */
        register();
    }

    /*
     * This method is called by the JCRE when installing the applet on the card.
     */
    public static void install( byte bArray[], short bOffset, byte bLength )
            throws ISOException
    {
        new IdentityCard();
    }

    /*
     * If no tries are remaining, the applet refuses selection.
     * The card can, therefore, no longer be used for identification.
     */
    public boolean select()
    {
        if ( pin.getTriesRemaining() == 0 )
            return false;
        return true;
    }

    /*
     * This method is called when the applet is selected and an APDU arrives.
     */
    public void process( APDU apdu ) throws ISOException
    {
        //A reference to the buffer, where the APDU data is stored, is retrieved.
        byte[] buffer = apdu.getBuffer();

        //If the APDU selects the applet, no further processing is required.
        if ( this.selectingApplet() )
            return;

        //Check whether the indicated class of instructions is compatible with this applet.
        if ( buffer[ ISO7816.OFFSET_CLA ] != IDENTITY_CARD_CLA ) ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED );
        //A switch statement is used to select a method depending on the instruction
        switch ( buffer[ ISO7816.OFFSET_INS ] )
        {
            case VALIDATE_PIN_INS:
                validatePIN( apdu );
                break;
            case GET_SERIAL_INS:
                getSerial( apdu );
                break;
            case SHOULD_UPDATE_TIME_INS:
                shouldUpdateTime( apdu );
                break;
            case UPDATE_TIME_INS:
                updateTime( apdu );
                break;
            case TEST_SIGNATURE_INS:
                testSignature( apdu, timestampPublicKey,(short)0, (short)12, (short)256 );
                break;
            case CLEAR_INPUT_BUFFER_INS:
                currentInBufferOffset = 0;
                apdu.setOutgoing();
                apdu.setOutgoingLength( ( short ) 1 );
                apdu.sendBytesLong( new byte[]{ 0 }, (short) 0, (short)1 );
                break;
            case UPDATE_INPUT_BUFFER_INS:
                updateBuffer( apdu );
                break;
            case GET_OUTPUT_BUFFER_INS:
                getOutputBufferChunk( apdu );
                break;
            case AUTHENTICATE_SP_INS:
                authenticateSP( apdu );
                break;
            case CONFIRM_CHALLENGE_INS:
                confirmChallenge( apdu );
                break;
            //If no matching instructions are found it is indicated in the status word of the response.
            //This can be done by using this method. As an argument a short is given that indicates
            //the type of warning. There are several predefined warnings in the 'ISO7816' class.
            default:
                ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED );
        }
    }

    private void getOutputBufferChunk( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();

        short offset = buffer[ISO7816.OFFSET_CDATA];

        apdu.setOutgoing();
        apdu.setOutgoingLength( (short )240 );
        apdu.sendBytesLong( transientOutBuffer, (short)(offset * 240), (short)240 );
    }

    public byte[] getValidAfterTime( byte[] input )
    {
        short start = 40; //second value
        while ( 48 != input[start++] || 13 != input[start + 2] );

        byte[] output = new byte[12];
        for (short i = 0; i < 12; i++)
        {
            output[i] = input[start + i + 3];
        }

        return output;
    }

    public byte[] getValidBeforeTime( byte[] input )
    {
        short start = 60; //second value
        while ( 48 != input[start++] || 13 != input[start + 4] );

        byte[] output = new byte[12];
        for (short i = 0; i < 12; i++)
        {
            output[i] = input[start + i + 5];
        }

        return output;
    }

    public boolean compareTime( byte[] start, byte[] now, byte[] end )
    {
        boolean beforeOk = false;
        boolean afterOk = false;

        for (short i = 0; i < 12; i++)
        {
            beforeOk = beforeOk || start[i] < now[i];
            afterOk = afterOk || end[i] > now[i];
            if ( beforeOk && afterOk )
            {
                return true;
            } else if (start[i] > now[i] || end[i] < now[i])
            {
                return false;
            }
        }

        return false;
    }

    private void updateBuffer( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();
        short len = (short)(buffer[ISO7816.OFFSET_CDATA] & (short) 0xff);

        if( (short)(len + currentInBufferOffset ) > MAX_BUFFER_SIZE )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 0 }, (short) 0, (short)1 );

            return;
        }
        Util.arrayCopy( buffer, (short)(ISO7816.OFFSET_CDATA + 1), transientInBuffer, currentInBufferOffset, len );
        currentInBufferOffset += len;

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 1 }, (short) 0, (short)1 );
    }

    private void shouldUpdateTime( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();

        byte reqValidation = Util.arrayCompare( validationTime, (short)0, buffer, (short)ISO7816.OFFSET_CDATA, (short)8 );

        isTimeOK = (reqValidation == (byte)(-1) ? (byte)1 : (byte)0);

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ isTimeOK }, (short) 0, (short)1 );
    }

    private void updateTime( APDU apdu )
    {
        if( testSignature( apdu, timestampPublicKey, (short)0, (short)16, (short)256 ) != (byte) 1 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 1 }, (short) 0, (short)1 );

            return;
        }

        byte reqValidation = Util.arrayCompare( currentTime, (short)0, transientInBuffer, (short)0, (short)8 );

        if( reqValidation >= (byte)0 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 2 }, (short) 0, (short)1 );

            return;
        }

        Util.arrayCopy( transientInBuffer, (short)0, currentTime, (short)0, (short)8 );
        Util.arrayCopy( transientInBuffer, (short)8, validationTime, (short)0, (short)8 );

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 0 }, (short) 0, (short)1 );
    }

    private short getEncodedSize()
    {
        return (short)((short)((transientInBuffer[1] & 0xff) << 8) | ((short)transientInBuffer[0] & 0xff));
    }

    private void authenticateSP( APDU apdu )
    {
        byte isSignatureOK = testSignature( apdu, caPublicKey, (short)2, getEncodedSize(), (short)256 );

        if( isSignatureOK != 1 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 1 }, (short) 0, (short)1 );

            return;
        }

        if( false && !compareTime( getValidBeforeTime( transientInBuffer ), currentTime, getValidAfterTime( transientInBuffer ) ) )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 2 }, (short) 0, (short)1 );

            return;
        }

        // Generate random symmetric key

        aesKey =  (AESKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_AES, (short)128, true );
        byte[] keyBytes = JCSystem.makeTransientByteArray( (short)16, JCSystem.CLEAR_ON_RESET );

        RandomData rnd = RandomData.getInstance( RandomData.ALG_SECURE_RANDOM );
        rnd.generateData( keyBytes, (short)0, (short)16 );

        aesKey.setKey( keyBytes, (short)0 );

        Cipher rsaCipher = Cipher.getInstance( Cipher.ALG_RSA_PKCS1, false );
        RSAPublicKey certPublicKey = (RSAPublicKey) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PUBLIC, (short)2048, false );
        certPublicKey.setExponent( caExponent, (short)0, (short)caExponent.length );
        certPublicKey.setModulus( transientInBuffer, (short)35, (short)256 );
        rsaCipher.init( certPublicKey, Cipher.MODE_ENCRYPT );

        byte [] encryptedKey = JCSystem.makeTransientByteArray( (short)256, JCSystem.CLEAR_ON_RESET );
        short encryptedKeySize = rsaCipher.doFinal( keyBytes, (short)0, (short)keyBytes.length, encryptedKey, (short)0 );

        Cipher cipher = Cipher.getInstance( Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false );
        cipher.init( aesKey, Cipher.MODE_ENCRYPT );

        byte [] encryptedChallenge = JCSystem.makeTransientByteArray( (short)64, JCSystem.CLEAR_ON_RESET );

        // TODO: IF TESTED, USE SECURE RANDOM
        short off = cipher.update( challenge, (short)0, (short)16, encryptedChallenge, (short)0 );
        cipher.doFinal( transientInBuffer, (short)0, (short)16, encryptedChallenge, off );

        //byte [] combined = new byte[ (short)(encryptedKeySize + encryptedChallenge.length) ]; //TODO fill transient buffer here and add 2 instructions to read/clear it.

        Util.arrayCopy( encryptedKey, (short)0, transientOutBuffer, (short)0, encryptedKeySize );
        Util.arrayCopy( encryptedChallenge, (short)0, transientOutBuffer, encryptedKeySize, (short)encryptedChallenge.length );

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 0 }, (short) 0, (short)1 );
    }

    private void confirmChallenge( APDU apdu )
    {
        byte buffer[] = apdu.getBuffer();

        Cipher cipher = Cipher.getInstance( Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false );

        cipher.init( aesKey, Cipher.MODE_DECRYPT );

        byte[] decrypted = JCSystem.makeTransientByteArray( (short)16, JCSystem.CLEAR_ON_RESET );

        cipher.doFinal( buffer, (short)ISO7816.OFFSET_CDATA, (short)16, decrypted, (short)0 );

        byte isOK = 1;
        for( short i = 0; i< decrypted.length; i++ )
        {
            if( decrypted[i] != (byte)(challenge[i] + (byte)1) )
                isOK = 0;
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ isOK }, (short) 0, (short)1 );
    }

    private byte testSignature( APDU apdu, Key key, short off, short len1, short len2 )
    {
        Signature  signature = Signature.getInstance( Signature.ALG_RSA_SHA_PKCS1, false ) ;

        signature.init( key, Signature.MODE_VERIFY );
        byte isSignatureOK = ( signature.verify( transientInBuffer, off, len1, transientInBuffer, (short ) (len1 + off), len2 ) ? (byte)1 : (byte)0);

        return isSignatureOK;
    }

    /*
     * This method is used to authenticate the owner of the card using a PIN code.
     */
    private void validatePIN( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();
        //The input data needs to be of length 'PIN_SIZE'.
        //Note that the byte values in the Lc and Le fields represent values between
        //0 and 255. Therefore, if a short representation is required, the following
        //code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        if ( buffer[ ISO7816.OFFSET_LC ] == PIN_SIZE )
        {
            //This method is used to copy the incoming data in the APDU buffer.
            apdu.setIncomingAndReceive();
            //Note that the incoming APDU data size may be bigger than the APDU buffer
            //size and may, therefore, need to be read in portions by the applet.
            //Most recent smart cards, however, have buffers that can contain the maximum
            //data size. This can be found in the smart card specifications.
            //If the buffer is not large enough, the following method can be used:
            //
            //byte[] buffer = apdu.getBuffer();
            //short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
            //Util.arrayCopy(buffer, START, storage, START, (short)5);
            //short readCount = apdu.setIncomingAndReceive();
            //short i = ISO7816.OFFSET_CDATA;
            //while ( bytesLeft > 0){
            //	Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
            //	bytesLeft -= readCount;
            //	i+=readCount;
            //	readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
            //}
            if ( pin.check( buffer, ISO7816.OFFSET_CDATA, PIN_SIZE ) == false )
                ISOException.throwIt( SW_VERIFICATION_FAILED );
        }
        else ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
    }

    /*
     * This method checks whether the user is authenticated and sends
     * the identity file.
     */
    private void getSerial( APDU apdu )
    {
        //If the pin is not validated, a response APDU with the
        //'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
        if ( !pin.isValidated() ) ISOException.throwIt( SW_PIN_VERIFICATION_REQUIRED );
        else
        {
            //This sequence of three methods sends the data contained in
            //'identityFile' with offset '0' and length 'identityFile.length'
            //to the host application.
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) serial.length );
            apdu.sendBytesLong( serial, ( short ) 0, ( short ) serial.length );
        }
    }
}
