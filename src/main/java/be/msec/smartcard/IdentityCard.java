package be.msec.smartcard;

import be.msec.DataUtils;
import com.licel.jcardsim.crypto.RSAKeyImpl;
import com.licel.jcardsim.crypto.SymmetricCipherImpl;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

import java.math.BigInteger;
import java.util.Random;

public class IdentityCard extends Applet
{
    private final static byte IDENTITY_CARD_CLA = ( byte ) 0x80;

    private static final byte VALIDATE_PIN_INS = 0x22;
    private static final byte GET_SERIAL_INS   = 0x24;

    private static final byte SHOULD_UPDATE_TIME_INS  = 0x26;
    private static final byte UPDATE_TIME_INS  = 0x27;

    private static final byte TEST_SIGNATURE_INS  = 0x28;

    private static final byte CLEAR_BUFFER_INS = 0x30;
    private static final byte UPDATE_BUFFER_INS = 0x31;

    private final static byte PIN_TRY_LIMIT = ( byte ) 0x03;
    private final static byte PIN_SIZE      = ( byte ) 0x04;

    private final static short SW_VERIFICATION_FAILED       = 0x6300;
    private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

    private final static byte TEST_ENCRYPTION_INS = 0x50;
    private final static byte CONFIRM_CHALLENGE_INS = 0x51;

    private byte[] serial = new byte[]{ 0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05 };
    private OwnerPIN pin;

    /**
     *  TimeStamp:
     * */
    private byte[] currentTime = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    private static final byte[] timeDelta = new byte[] {0, 0, 0, 0, 5, 38, 92, 0}; //24 hours
    private byte isTimeOK = 0;
    private byte[] timestampExponent = new byte[] {1, 0, 1};
    private byte[] timestampModulus = new byte[] { -96, -90, -100, -32, 75, -91, 47, 44, -118, 34, -110, 90, -63, -43, -113, -116, 10, -9, -69, 42, -13, -25, 67, -22, 85, 114, -25, -3, 72, 63, 115, -105, 65, 82, 121, -49, 26, 21, 44, -108, 33, -110, 51, 37, -50, 32, -40, 0, -66, 113, -37, 65, -85, 48, -46, 1, 102, 14, -99, -57, 20, -2, 71, 49, -8, -63, 20, -87, -11, -117, 89, 41, -120, 5, -72, -70, 86, -4, -80, 48, -52, -30, -111, 85, -81, 85, -43, 67, 93, -15, -40, -21, 46, -84, 24, 4, 10, 105, -82, 30, 7, -21, 43, -121, -11, -66, -110, 122, 1, -83, -79, 4, -49, -5, 88, -56, -56, -10, 45, -113, 57, -15, 23, -30, 103, 53, -41, -29, 121, 45, 47, -71, 39, -71, 99, -81, -79, 39, -104, 62, -114, -28, 13, -97, 51, -128, -13, -100, 54, 125, -31, -5, 80, 81, -20, 66, 118, 110, 75, -29, -33, -97, -28, -40, 41, -114, 58, 47, -75, 89, 87, 62, 27, 3, -1, 58, 47, 59, -36, -34, -51, -111, -87, -58, -47, 119, 47, 40, 78, -99, -11, -5, 104, 1, -11, -95, -32, -96, 21, 9, -1, -21, -58, -123, 105, 119, -77, 45, -121, 117, 110, -42, -101, -43, 87, 60, 119, -53, -49, -92, -52, -101, -95, -94, 97, -11, -120, -50, 118, -3, 105, 96, -44, -54, -96, 122, -125, -94, 33, 27, 71, -81, -5, -114, -62, 93, 85, 109, 121, 55, 81, 38, -119, -82, -94, -9 };
    private RSAPublicKey timestampPublicKey;

    /*
    *   Transient buffer
    * */
    private short currentOffset = 0;
    private byte[] transientBuffer;
    private short MAX_BUFFER_SIZE = 1024;


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

        timestampPublicKey = (RSAPublicKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PUBLIC, (short)5, false );
        timestampPublicKey.setExponent( timestampExponent, (short)0, (short) timestampExponent.length );
        timestampPublicKey.setModulus( timestampModulus, (short)0, (short) timestampModulus.length );

        transientBuffer = JCSystem.makeTransientByteArray( MAX_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET );

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
                testSignature( apdu );
                break;
            case CLEAR_BUFFER_INS:
                currentOffset = 0;
                apdu.setOutgoing();
                apdu.setOutgoingLength( ( short ) 1 );
                apdu.sendBytesLong( new byte[]{ 0 }, (short) 0, (short)1 );
                break;
            case UPDATE_BUFFER_INS:
                updateBuffer( apdu );
                break;
            case TEST_ENCRYPTION_INS:
                test( apdu );
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

    private void updateBuffer( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();
        short len = (short)(buffer[ISO7816.OFFSET_CDATA] & (short) 0xff);

        if( (short)(len + currentOffset) > MAX_BUFFER_SIZE )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 0 }, (short) 0, (short)1 );

            return;
        }
        Util.arrayCopy( buffer, (short)(ISO7816.OFFSET_CDATA + 1), transientBuffer, currentOffset, len );
        currentOffset += len;

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 1 }, (short) 0, (short)1 );
    }

    private void shouldUpdateTime( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();

        byte reqValidation = Util.arrayCompare( DataUtils.add( currentTime, timeDelta ), (short)0, buffer, (short)ISO7816.OFFSET_CDATA, (short)8 );

        isTimeOK = (reqValidation == (byte)(-1) ? (byte)1 : (byte)0);

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ isTimeOK }, (short) 0, (short)1 );
    }

    private void updateTime( APDU apdu )
    {
        if( testSignature( apdu ) != (byte) 1 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 1 }, (short) 0, (short)1 );

            return;
        }

        byte reqValidation = Util.arrayCompare( DataUtils.add( currentTime, timeDelta ), (short)0, transientBuffer, (short)ISO7816.OFFSET_CDATA, (short)8 );

        if( reqValidation >= (byte)0 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 2 }, (short) 0, (short)1 );

            return;
        }

        Util.arrayCopy( transientBuffer, (short)0, currentTime, (short)0, (short)8 );

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 0 }, (short) 0, (short)1 );
    }

    private void test( APDU apdu )
    {
        aesKey =  (AESKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_AES, (short)128, true );
        byte[] keyBytes = JCSystem.makeTransientByteArray( (short)16, JCSystem.CLEAR_ON_RESET );

        RandomData rnd = RandomData.getInstance( RandomData.ALG_SECURE_RANDOM );
        rnd.generateData( keyBytes, (short)0, (short)16 );

        aesKey.setKey( keyBytes, (short)0 );

        Cipher cipher = Cipher.getInstance( Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false );

        cipher.init( aesKey, Cipher.MODE_ENCRYPT );

        byte [] outputArray = JCSystem.makeTransientByteArray( (short)64, JCSystem.CLEAR_ON_RESET );

        cipher.doFinal( challenge, (short)0, (short)16, outputArray, (short)0 );

        byte [] combined = new byte[ keyBytes.length + outputArray.length ];

        Util.arrayCopy( keyBytes, (short)0, combined, (short)0, (short)keyBytes.length );
        Util.arrayCopy( outputArray, (short)0, combined, (short)keyBytes.length, (short)outputArray.length );

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) combined.length );
        apdu.sendBytesLong( combined, (short) 0, (short)combined.length );
    }

    private void encryptKey()
    {
        Cipher cipher = Cipher.getInstance( Cipher.ALG_RSA_PKCS1, false );

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

    private byte testSignature( APDU apdu )
    {
        short len1 = 8;
        short len2 = 256;

        Signature  signature = Signature.getInstance( Signature.ALG_RSA_SHA_PKCS1, false ) ;

        signature.init( timestampPublicKey, Signature.MODE_VERIFY );
        byte isSignatureOK = ( signature.verify( transientBuffer, (short)0, len1, transientBuffer, len1, len2 ) ? (byte)1 : (byte)0);

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
