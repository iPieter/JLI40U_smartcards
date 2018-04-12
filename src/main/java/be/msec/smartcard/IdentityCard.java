package be.msec.smartcard;

import be.msec.DataUtils;
import com.licel.jcardsim.crypto.RSAKeyImpl;
import javacard.framework.*;
import javacard.security.*;

import java.math.BigInteger;

public class IdentityCard extends Applet
{
    private final static byte IDENTITY_CARD_CLA = ( byte ) 0x80;

    private static final byte VALIDATE_PIN_INS = 0x22;
    private static final byte GET_SERIAL_INS   = 0x24;
    private static final byte UPDATE_TIME_INS  = 0x26;
    private static final byte TEST_SIGNATURE_INS  = 0x28;

    private final static byte PIN_TRY_LIMIT = ( byte ) 0x03;
    private final static byte PIN_SIZE      = ( byte ) 0x04;

    private final static short SW_VERIFICATION_FAILED       = 0x6300;
    private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

    private byte[] serial = new byte[]{ 0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05 };
    private OwnerPIN pin;

    /**
     *  TimeStamp:
     * */
    private byte[] currentTime = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    private static final byte[] timeDelta = new byte[] {0, 0, 0, 0, 5, 38, 92, 0}; //24 hours
    private byte isTimeOK = 0;
    private byte[] timestampExponent = new byte[] {1, 0, 1};
    private byte[] timestampModulus = new byte[] {0, -116, 35, -92, 85, 71, 55, -43, 71, -69, 111, 122, -103, -61, -6, 95, -29, -126, -91, -79, 0, 61, 42, 27, -88, 38, -91, 23, 42, -116, -60, 118, -111, -3, -120, -8, 116, 10, 92, 75, -82, -81, -2, -111, -24, -59, -18, -47, 61, -71, -89, -96, -109, 76, 84, 57, 87, -89, -32, 124, -74, -41, -74, 19, -3, -122, 20, 27, 115, 57, -123, 2, -15, 39, 97, 51, -1, -15, 123, -9, 127, -93, 85, 107, -26, 71, -67, -29, -86, 35, -18, -105, -109, -41, -40, 11, 28, -49, 85, -76, -10, 5, -105, -22, 22, 4, 59, -7, 23, -110, 12, 19, -114, 107, 48, 66, -32, -45, 2, -105, 78, -67, -51, 87, 3, -29, -101, -36, -29, 2, -14, 47, -69, -95, -113, 7, -14, 107, 66, -81, 69, -80, -63, -37, 36, 88, -110, 91, -31, 91, -33, -19, 125, 65, -36, 55, 41, -48, 9, -31, 36, 66, 100, 10, 45, 55, -114, -60, -51, -13, -79, 3, -31, 114, 17, -7, -6, -82, 100, -79, 119, -27, 80, -80, -109, 38, 48, -101, -28, -47, 57, 106, -5, 103, -35, -72, 126, 101, 98, -33, -1, -65, -112, 106, -84, 83, -18, 99, 84, 107, -83, 100, -62, 11, -46, 73, -41, -17, 73, -28, 86, 12, 20, -61, 120, -51, 84, -21, -89, 51, 98, 60, -73, -65, -100, -88, -98, 72, 5, -115, -80, 123, 53, 32, -78, -49, 33, -27, 0, 78, -104, -110, -57, 9, 90, 2, -97};
    private RSAPublicKey timestampPublicKey;

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
            case UPDATE_TIME_INS:
                shouldUpdateTime( apdu );
                break;
            case TEST_SIGNATURE_INS:
                testSignature( apdu );
                break;
            //If no matching instructions are found it is indicated in the status word of the response.
            //This can be done by using this method. As an argument a short is given that indicates
            //the type of warning. There are several predefined warnings in the 'ISO7816' class.
            default:
                ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED );
        }
    }

    private void shouldUpdateTime( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();

        byte reqValidation = Util.arrayCompare( DataUtils.add( currentTime, timeDelta ), (short)0, buffer, (short)0, (short)8 );

        isTimeOK = (byte)(reqValidation == (byte)(-1) ? (byte)1 : (byte)0);

        Util.arrayCopy( buffer, (short)0, currentTime, (short)0, (short)8 );

        // Note(Anton): This changes the buffer so do this after any operation on it

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ isTimeOK }, (short) 0, (short)1 );
    }

    private void testSignature( APDU apdu )
    {
        byte [] buffer = apdu.getBuffer();

        Signature  signature = Signature.getInstance( Signature.ALG_RSA_SHA_PKCS1, false ) ;

        signature.init( timestampPublicKey, Signature.MODE_VERIFY );
        byte isSignatureOK = ( signature.verify( buffer, (short)0, (short)8, buffer, (short)8, (short)16 ) ? (byte)1 : (byte)0);

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ isSignatureOK }, (short) 0, (short)1 );
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
