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
    private byte[] timestampModulus = new byte[] { -72, -32, 55, -37, -20, -64, -115, 15, -100, 35, 37, 22, 113, -102, -114, -111, 93, 102, 111, 44, -113, -118, 120, -55, 56, -5, -47, -49, -76, -125, -45, -70, 112, -119, -108, 23, -46, -79, 107, -69, -112, 51, 67, 39, -126, 127, -110, 79, -50, 34, 74, -18, 88, -67, -97, 115, -85, -58, 9, -88, 8, -108, -52, 1, -65, -34, 79, -103, 98, 119, -46, 125, -123, -111, 100, -50, -118, -59, 48, 98, 122, 33, -99, 34, -29, 112, 53, -90, -117, 18, 74, 73, -70, -88, 103, 40, 76, -76, 5, -48, -3, 42, 69, 93, 4, 80, 106, -57, 110, 89, -79, -115, 28, 21, 50, -126, -120, 127, -90, -119, -15, -92, -127, 74, -101, -37, 101, -116, 75, -122, -17, 92, 117, -43, 72, -72, 88, 24, 60, 15, -70, -4, 55, 62, 110, 53, -6, -11, -4, -84, 83, -51, -99, 107, 22, -120, -48, 117, -62, -119, -68, -1, -3, -113, -96, -37, -45, 47, 56, -94, 115, -48, -17, 98, -92, -19, 22, -128, 48, 32, 29, -37, -104, -52, 101, 45, 113, 26, -95, 124, -9, -104, 101, 25, 114, 101, -79, 87, 78, 17, 116, 18, -52, -120, -62, -68, 98, 9, -54, 96, -31, -26, 100, 105, 102, 93, -66, -37, 93, 21, -86, -47, -30, 1, 110, -92, -125, -96, -18, -41, 28, 117, 84, -3, 5, 90, 81, 43, -96, -88, -98, 25, -69, -94, 83, 75, 112, -97, -111, -7, -5, -29, 107, 127, 126, -31 };
    private RSAPublicKey timestampPublicKey;

    /**
     *  CA PK
     * */
    private byte[] caExponent = new byte[] {1, 0, 1};
    private byte[] caModulus = new byte[] {-121, -45, -127, -108, -25, 90, 111, 50, -77, -105, -53, 79, -33, 106, 119, -54, -19, 51, 115, -117, -84, 19, 34, -84, -78, -14, -114, 97, -18, 109, -115, 59, -22, 7, 86, -92, -47, 28, -106, 99, -102, -80, 117, 32, -81, -81, -61, 34, 9, -77, 0, 96, 27, 106, 89, -29, -97, -4, -74, -13, 103, -58, 127, 62, 126, -15, -120, -68, 5, -113, -1, -92, 7, -103, -11, -63, 93, 27, -73, 99, -25, -52, 35, 71, -81, 110, 103, 97, 14, -81, -66, -104, 118, 24, 91, -2, 120, -114, 101, -67, 31, 119, -64, 67, -38, 34, -64, -51, -99, 70, -12, 114, 49, 17, 55, -48, 59, -25, 65, 119, 31, -70, -86, 22, 67, -63, -73, -82, 94, 105, 71, 54, -28, -17, -74, 28, 110, 72, -75, -50, 32, -84, -44, 105, -22, -96, 95, 27, 37, 112, 0, 4, -29, -20, 19, -77, -21, 83, -55, 40, -15, -29, -112, 39, -127, -87, 121, -80, 100, 54, -128, -79, -99, 16, -91, 91, -26, 110, -31, 125, -25, -54, 104, -20, 30, -65, 5, 63, 92, -38, -57, 91, -48, 30, -120, 54, -29, -72, -108, -105, 37, -81, -99, -52, 41, 126, 104, -24, -54, -108, -65, -75, 1, -97, 63, 16, 122, -110, -82, 48, -36, 17, 77, 74, 4, 33, 46, 122, -24, -59, -57, 37, 54, 69, -41, -115, -99, -70, -43, 31, -111, -44, -74, -43, 17, 32, -81, -94, 115, -52, 74, 62, 63, -76, 121, -83};
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
