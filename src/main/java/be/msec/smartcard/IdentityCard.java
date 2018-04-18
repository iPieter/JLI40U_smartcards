package be.msec.smartcard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class IdentityCard extends Applet
{
    private final static byte IDENTITY_CARD_CLA = ( byte ) 0x80;

    private static final byte VALIDATE_PIN_INS = 0x22;
    private static final byte GET_SERIAL_INS   = 0x24;

    private static final byte SHOULD_UPDATE_TIME_INS = 0x26;
    private static final byte UPDATE_TIME_INS        = 0x27;

    private static final byte TEST_SIGNATURE_INS = 0x28;

    private static final byte CLEAR_INPUT_BUFFER_INS  = 0x30;
    private static final byte UPDATE_INPUT_BUFFER_INS = 0x31;
    private static final byte GET_OUTPUT_BUFFER_INS   = 0x32;

    private final static byte PIN_TRY_LIMIT = ( byte ) 0x03;
    private final static byte PIN_SIZE      = ( byte ) 0x04;

    private final static short SW_VERIFICATION_FAILED       = 0x6300;
    private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

    private final static byte AUTHENTICATE_SP_INS   = 0x50;
    private final static byte CONFIRM_CHALLENGE_INS = 0x51;

    private final static byte AUTHENTICATE_CARD_INS = 0x60;

    private byte[] serial = new byte[]{ 0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05 };
    private OwnerPIN pin;

    /**
     * TimeStamp:
     */
    private byte[] currentTime       = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    private byte[] validationTime    = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    private byte   isTimeOK          = 0;
    private byte[] timestampExponent = new byte[]{ 1, 0, 1 };
    private byte[] timestampModulus  = new byte[]{ -123, 6, 30, -1, -126, 77, 91, 95, 17, -14, 8, 127, 76, -55, 120, 114, -72, -55, 73, -49, 112, 125, 105, 28, 87, 90, 13, -57, 75, 87, 18, 86, 74, 65, -96, -89, -93, -80, -53, -28, 93, 30, 71, 32, 14, 124, 110, -55, 107, -47, 26, 15, 54, -61, 125, 114, 14, -11, 122, 63, -55, -64, -128, -54, -32, 119, 73, 48, -83, -123, -9, -85, -3, 5, -8, -6, 123, 102, -121, -120, -1, 107, -23, 85, -64, 78, 50, -38, -107, 100, 89, 60, 41, 13, -91, 27, -4, 29, -58, 125, -37, -30, 94, -70, -8, -60, 32, 72, 1, 69, -1, 70, 24, -11, -98, -74, -33, -97, -115, -66, 92, -100, 108, -97, 93, -98, -47, -120, -25, 57, 0, -1, 118, -62, 56, -94, 69, 107, -46, 85, -87, -121, -51, 48, -75, 53, -66, 73, -37, -14, -87, 78, -107, 120, 114, 18, -120, -18, 94, -79, -77, -24, 12, -128, -56, -15, 67, -11, 15, -18, -1, 51, -1, -98, 101, 113, -49, -6, 77, 117, 120, 52, 89, -32, -8, 108, 29, 72, 111, -96, -9, -78, -4, -72, -10, -65, 114, 65, -121, 118, -1, -39, 3, 15, 79, -25, 69, -90, 15, -99, 81, 43, -89, 80, -87, -69, -49, -83, -46, 21, -23, -121, -53, -84, -118, 121, -60, -19, -87, -89, -126, 115, 43, 121, -88, -18, -100, 68, 50, 43, -69, -124, 107, -40, 91, 125, 64, 87, -95, 58, 41, 22, -16, -103, 57, -55 };
    private RSAPublicKey timestampPublicKey;

    /**
     * CA PK
     */
    private byte[] caExponent = new byte[]{ 1, 0, 1 };
    private byte[] caModulus  = new byte[]{ -32, -46, -12, -101, 25, 10, 111, 80, 80, -6, 118, -46, -71, 93, -94, 19, -94, 50, 3, -93, 54, -31, 108, 80, 113, 59, 50, -28, -14, -42, -66, 58, 27, -84, -58, -99, 101, 34, 71, 108, 118, -56, -5, -128, 108, -13, -16, 55, 66, 97, -76, -59, -78, -106, 39, 21, 94, -92, 14, -98, 48, -79, 28, 100, 51, 109, 23, 68, -82, 93, 6, 106, -19, -124, 39, 65, 11, 52, -34, 71, 96, -15, 13, -40, 76, 100, 101, 101, -22, -43, -114, 106, 87, -73, -99, 99, -60, -123, -123, 119, -118, 30, -60, -103, -9, -110, 36, -52, -26, -2, -82, 117, -119, 46, 115, -111, 72, -27, -50, 7, 11, 110, 91, 86, -56, -9, -79, -106, -113, -4, -59, -22, -127, -87, -97, -109, -2, -64, -122, 45, 76, -128, -103, 102, -3, 108, -107, -12, 24, 54, 121, 115, 121, -82, -14, -21, 20, 23, -126, -117, 37, -99, 57, 26, 105, 58, -4, -93, 117, 36, 41, -94, 64, 48, -5, -119, 62, 81, -106, -108, 115, 76, 113, -53, -33, 62, 31, 68, -90, -33, -120, -68, 125, 59, -106, 48, -124, -92, 89, -101, 65, -49, 56, 117, 108, -34, -72, 119, -112, 90, 121, -95, -15, -5, 2, 87, 101, 55, 14, -50, -48, 99, -128, -60, -36, -43, -28, -88, 70, -25, -119, 6, 53, 74, 84, -11, -65, -91, -43, -85, -54, -91, -61, -103, 65, 98, -5, -6, -87, -27, -2, -67, -77, 64, -126, -127 };
    private RSAPublicKey caPublicKey;

    /**
     * Shared Certificate & SK
     */
    private byte[] sharedExpontent = new byte[]{ -122, -34, 91, -59, -106, 77, 28, 18, -57, 12, 36, -65, -19, 31, 69, -92, -18, 100, -111, 75, 8, 98, 86, -99, 13, -98, 99, 122, -8, 117, 78, -64, 54, 126, 91, -61, 83, 67, 81, 80, 42, 35, 76, -34, -17, -7, -68, 27, 54, -55, -29, -86, -89, -16, 43, -97, 16, -85, -51, 107, 113, 25, -60, 31, 124, -16, 86, 53, 32, 112, -123, 53, 2, 41, 99, -120, 108, -100, 65, -62, 113, -78, 111, 112, 20, -96, -74, 9, 82, -37, 27, 106, 77, -54, -75, 23, -25, -29, -56, 87, 1, 30, -82, 81, 44, 74, 115, 1, 88, 123, -65, 48, -61, -128, -89, 56, 47, 57, -127, -119, 45, 68, -13, 82, -71, 125, -17, -13, 96, -78, -74, 122, 127, -5, 88, 11, -65, -47, -68, 50, 98, -62, 78, -41, -23, 15, -39, -107, 74, -5, -50, 125, 116, -25, -2, -71, 41, -91, -108, 98, 18, 64, -35, 63, -4, -17, 82, 71, -88, -61, -45, 74, -35, -82, -122, -123, -77, 72, -122, -59, -114, 90, 52, 115, -84, -117, -88, 3, 45, -119, 42, -18, 92, -42, 54, -40, 83, 4, 31, -56, -43, -23, 51, 91, -2, -30, -98, 82, -89, 31, -79, -57, 47, -115, -120, -79, -53, -36, -86, -92, 108, -85, -68, 23, -88, 4, 125, -88, 24, -32, 65, 23, -109, -107, -9, -55, 99, -106, 86, -16, -4, 6, 42, -117, -23, 99, 83, -1, -76, 32, -125, -89, 38, 4, -17, -79 };
    private byte[] sharedCert      = new byte[]{ 48, 48, 48, 48, 48, 48, 48, 83, 77, 65, 82, 84, 67, 65, 82, 68, 90, 0, 0, 1, 98, -55, 74, 51, 80, 0, 0, 1, 99, 104, -17, 87, 80, -111, -26, -30, -122, 114, 90, 6, -29, 50, -92, 26, 16, -112, 123, -67, -41, -79, -22, 30, 37, 17, 31, -47, -30, -43, -70, 60, -48, 114, -119, 44, 65, 20, -18, -70, -1, 22, 92, 116, 13, -63, -73, -5, 10, 59, -18, -79, 18, 63, 15, -81, 5, 36, 28, -51, 3, 92, 87, 41, 32, 65, -32, 69, 18, 39, 113, 64, 42, 107, -72, -92, 125, 76, -105, -27, -67, -117, -25, -102, 35, 24, -59, 84, -114, 30, -32, 108, 125, -14, -84, 127, 3, -40, -89, 116, 5, 62, 124, 28, 117, -94, 82, -126, 114, -67, 116, -97, -104, -33, 105, 83, 75, -67, -78, 16, 56, -46, 63, 28, 75, 84, -30, 20, 122, 2, 92, 91, 8, -71, -22, 118, -48, 103, -63, 47, 112, -78, -33, 85, 82, 7, -84, -75, -119, 17, -8, 121, 60, 36, 80, -56, 3, 37, -64, -21, -109, 95, 3, -116, -120, 61, -103, -15, 31, -50, -53, -116, 119, -71, 40, -6, -74, 77, -19, 66, -11, -74, 114, 58, -93, -62, -12, 60, -63, 97, 86, -127, -21, 102, 24, 110, -59, -30, -77, -83, -111, -112, -45, 89, 112, -5, 51, -77, -21, 34, 26, -88, -60, 32, 67, -37, 22, -115, -28, 62, 10, 31, -44, 92, -54, -36, 31, -78, -24, 40, 29, 45, 40, 122, -98, 61, 93, 24, -16, 0, 8, -85, -105, 114, -12, -41, -121, -78, 48, -67, 79, 67, -57, 69, 14, -25, -3, -70, 71, -1, 119, 57, -43, 29, -54, -124, 7, -96, -35, -123, -128, -114, -114, -116, 114, -82, 109, -99, -64, 68, 105, -28, -34, 32, -123, 52, 90, 49, 78, -22, -55, -111, 92, 25, 53, -85, -7, 92, 67, 102, -110, 6, -44, 20, -114, -59, 108, 67, 126, -81, 92, -114, -106, 3, 61, 65, -111, -110, 78, -107, -64, 82, -88, 25, -102, -77, 52, 71, -47, 85, 107, -45, 43, 55, 110, 84, -59, -52, 7, -31, 63, -8, -101, 15, 25, -37, 10, -66, -88, 37, -100, 5, -125, -98, -5, -59, 2, -51, -110, 108, -20, -110, 5, 100, -120, -95, 94, -47, 71, -115, 42, -106, 82, -57, 94, -89, -58, -53, 34, 97, 68, 68, 54, -78, 9, 26, 4, 47, -72, 110, -101, 42, -119, 7, 115, -96, -79, 22, 39, -98, -73, -78, 72, -84, -35, -41, 43, -17, 81, 79, -97, -27, -122, 110, 27, -49, -34, -34, -44, 10, 55, -90, -66, -62, 11, -60, 51, 23, 34, 48, 98, 18, 111, -94, -17, 59, 105, -30, 112, 7, 37, -121, 73, 23, -11, -87, 10, -121, -85, -105, -86, -99, -73, -102, -89, -50, 14, 62, 125, 1, -98, 8, -97, -128, 56, 15, 73, -70, 93, -14, 26, 100, -75, 90, 22, -124, -27, 52, -124, 39, -39, -22, -15, 117, 29, -23, 7, -9, -50, -109, 38, -87, 23, -68, -113, 73, 28, 4, -1, 11, -86, 60, -95, 97, 85, 7, -44, 35, 85, -37, -48, -25, 22, -36, 99, 41, 53 };
    private RSAPrivateKey sharedPrivateKey;

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
    private byte[] challenge;
    private boolean auth;


    /**
     * Citizen data
     * - identifier = calculated(32 + 16bytes) =[H]=> 64 bytes
     * - name       = 64 bytes
     * - address    = 64 bytes
     * - country    = 2 bytes
     * - birth date = 8 bytes
     * - age        = calculated(1byte)
     * - gender     = 1 byte
     * +++++++++++++++++++++++++++
     * SUM = 204
     * - picture    = max 820 bytes
     */
    private byte[] identifier = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0 };
    private byte[] name       = new byte[]{48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 66, 111, 98, 32, 66, 111, 98, 122, 111, 111, 110};
    private byte[] address       = new byte[]{48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 76, 97, 110, 103, 101, 119, 101, 103, 115, 116, 114, 97, 97, 116, 32, 51};
    private byte[] country       = new byte[]{66, 69};
    private byte[] birthDay       = new byte[]{49, 57, 57, 48, 48, 52, 48, 52};
    private byte[] gender       = new byte[]{77};
    private byte[] picture       = new byte[]{-1, -40, -1, -32, 0, 16, 74, 70, 73, 70, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, -1, -37, 0, 67, 0, 16, 16, 16, 16, 17, 16, 18, 20, 20, 18, 25, 27, 24, 27, 25, 37, 34, 31, 31, 34, 37, 56, 40, 43, 40, 43, 40, 56, 85, 53, 62, 53, 53, 62, 53, 85, 75, 91, 74, 69, 74, 91, 75, -121, 106, 94, 94, 106, -121, -100, -125, 124, -125, -100, -67, -87, -87, -67, -18, -30, -18, -1, -1, -1, -1, -37, 0, 67, 1, 16, 16, 16, 16, 17, 16, 18, 20, 20, 18, 25, 27, 24, 27, 25, 37, 34, 31, 31, 34, 37, 56, 40, 43, 40, 43, 40, 56, 85, 53, 62, 53, 53, 62, 53, 85, 75, 91, 74, 69, 74, 91, 75, -121, 106, 94, 94, 106, -121, -100, -125, 124, -125, -100, -67, -87, -87, -67, -18, -30, -18, -1, -1, -1, -1, -64, 0, 17, 8, 0, 64, 0, 48, 3, 1, 34, 0, 2, 17, 1, 3, 17, 1, -1, -60, 0, 27, 0, 0, 2, 2, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 6, 4, 5, 1, 2, 7, 0, -1, -60, 0, 40, 16, 0, 2, 2, 1, 3, 3, 3, 4, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 3, 4, 5, 17, 33, 18, 19, 49, 6, 34, 50, 20, 35, 81, 113, 65, 97, -95, -1, -60, 0, 24, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4, 2, 0, 1, -1, -60, 0, 30, 17, 0, 3, 1, 1, 1, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 17, 3, 33, 18, 113, 19, 49, 97, -1, -38, 0, 12, 3, 1, 0, 2, 17, 3, 17, 0, 63, 0, 119, -56, -55, -81, 26, -78, -17, 20, 50, 117, -100, -21, -9, -19, 30, -46, 67, -25, -28, -3, 102, 83, 40, 111, -73, 92, -85, 116, 98, 118, 30, 4, 11, -73, -72, -121, -25, -49, 65, 49, -52, -69, -25, -112, -19, -5, 51, -56, -6, -106, 25, 54, -41, 97, -32, 73, 117, -114, -111, -52, 41, 112, 70, -48, 126, 116, -103, 71, -30, 88, 90, 105, 126, -95, -85, 49, -110, -85, -109, -94, -61, 25, 103, 32, -55, 29, -116, -125, -73, 3, -56, -99, 31, 67, -52, 108, -52, 4, 119, 126, -89, 82, 81, -91, 81, 90, -120, -18, 113, -117, 24, 79, -44, -73, -105, -7, 117, 77, -119, -104, 122, 27, 23, 84, -55, -96, -4, 91, -36, -97, -88, 27, -14, 42, -84, -20, 108, 19, 22, -118, 56, -46, -64, -37, -49, 109, -68, -118, 109, 38, -78, -21, -56, -112, -123, -39, 54, 55, -98, 63, 27, -19, 9, -50, -114, -21, 51, -61, 26, -91, 71, 101, 120, -51, -24, -9, -5, 25, 85, -106, -14, -32, -54, -105, -88, -37, -114, 81, -4, -111, 13, -23, -11, 116, -51, -92, 114, 15, -68, 48, -101, -25, 89, -120, -97, -89, 61, 109, -1, 0, 11, -3, 114, -109, -34, -60, -72, 14, 7, 82, 19, -8, -22, -118, -106, -32, -41, -42, 73, 60, 78, -123, -101, 79, 123, 26, -60, -37, 115, -28, 78, 123, -106, -18, 28, -95, -33, -52, 75, 51, -57, 26, 122, 74, -82, -92, -82, -96, -93, -60, 11, 88, 43, 111, 0, -113, -22, 2, -62, -36, 125, -33, -10, 107, -42, -127, 118, 85, 44, 96, -75, -18, -108, -86, -13, -12, 78, 91, -125, 109, 46, 52, -118, 55, -52, 54, 116, -98, 1, -26, 46, -46, -92, 111, -57, -13, 31, -76, -63, -74, 21, 63, -93, 61, -119, -37, -6, 11, -83, -28, -3, -109, -30, -90, -71, -124, 81, -66, -91, 7, -75, -72, 120, -41, 5, 106, 37, -107, 58, 56, 5, 74, -99, -29, -46, -44, 75, 52, -27, -100, -29, -80, -101, 117, 45, 96, -109, 55, 68, 97, -27, 64, -104, -78, -58, -93, 117, 28, -127, 35, -3, 75, 19, -64, -128, -53, 103, 73, 91, 0, -15, -29, 76, -76, 89, -119, 80, -37, -30, 34, 13, 101, -119, -36, -58, 77, 55, 84, -57, -59, -96, -91, -60, -113, 119, 6, 119, 58, -54, 49, -42, 42, -105, -119, -73, -89, -1, -39};

    private final byte IDENTIFIER_BIT = ( byte ) ( 1 << 7 );
    private final byte NAME_BIT       = ( byte ) ( 1 << 6 );
    private final byte ADDRESS_BIT    = ( byte ) ( 1 << 5 );
    private final byte COUNTRY_BIT    = ( byte ) ( 1 << 4 );
    private final byte BIRTHDAY_BIT   = ( byte ) ( 1 << 3 );
    private final byte AGE_BIT        = ( byte ) ( 1 << 2 );
    private final byte GENDER_BIT     = ( byte ) ( 1 << 1 );
    private final byte PICTURE_BIT    = ( byte ) ( 1 << 0 );

    private final byte E_GOV_MASK   = IDENTIFIER_BIT | NAME_BIT | ADDRESS_BIT | COUNTRY_BIT | BIRTHDAY_BIT | AGE_BIT | GENDER_BIT;
    private final byte SOC_NET_MASK = IDENTIFIER_BIT | NAME_BIT | COUNTRY_BIT | AGE_BIT | GENDER_BIT | PICTURE_BIT;
    private final byte DEFAULT_MASK = IDENTIFIER_BIT | AGE_BIT;

    private IdentityCard()
    {
        /*
         * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
        pin = new OwnerPIN( PIN_TRY_LIMIT, PIN_SIZE );
        pin.update( new byte[]{ 0x01, 0x02, 0x03, 0x04 }, ( short ) 0, PIN_SIZE );

        timestampPublicKey = ( RSAPublicKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PUBLIC, ( short ) 2048, false );
        timestampPublicKey.setExponent( timestampExponent, ( short ) 0, ( short ) timestampExponent.length );
        timestampPublicKey.setModulus( timestampModulus, ( short ) 0, ( short ) timestampModulus.length );

        caPublicKey = ( RSAPublicKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PUBLIC, ( short ) 2048, false );
        caPublicKey.setExponent( caExponent, ( short ) 0, ( short ) caExponent.length );
        caPublicKey.setModulus( caModulus, ( short ) 0, ( short ) caModulus.length );

        sharedPrivateKey = ( RSAPrivateKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PRIVATE, ( short ) 2048, false );
        sharedPrivateKey.setExponent( sharedExpontent, ( short ) 0, ( short ) sharedExpontent.length );
        sharedPrivateKey.setModulus( sharedCert, ( short ) ( sharedCert.length - 256 ), ( short ) 256 );

        transientInBuffer = JCSystem.makeTransientByteArray( MAX_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET );
        transientOutBuffer = JCSystem.makeTransientByteArray( MAX_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET );

        challenge = JCSystem.makeTransientByteArray( ( short ) 16, JCSystem.CLEAR_ON_RESET );

        for ( short i = 0; i < ( short ) 16; i++ )
            challenge[ i ] = ( byte ) i;

        auth = false;

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
                testSignature( apdu, timestampPublicKey, ( short ) 0, ( short ) 12, ( short ) 256 );
                break;
            case CLEAR_INPUT_BUFFER_INS:
                currentInBufferOffset = 0;
                apdu.setOutgoing();
                apdu.setOutgoingLength( ( short ) 1 );
                apdu.sendBytesLong( new byte[]{ 0 }, ( short ) 0, ( short ) 1 );
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
            case AUTHENTICATE_CARD_INS:
                authenticateCard( apdu );
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

        short offset = buffer[ ISO7816.OFFSET_CDATA ];

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 240 );
        apdu.sendBytesLong( transientOutBuffer, ( short ) ( offset * 240 ), ( short ) 240 );
    }

    private void updateBuffer( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();
        short  len    = ( short ) ( buffer[ ISO7816.OFFSET_CDATA ] & ( short ) 0xff );

        if ( ( short ) ( len + currentInBufferOffset ) > MAX_BUFFER_SIZE )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 0 }, ( short ) 0, ( short ) 1 );

            return;
        }
        Util.arrayCopy( buffer, ( short ) ( ISO7816.OFFSET_CDATA + 1 ), transientInBuffer, currentInBufferOffset, len );
        currentInBufferOffset += len;

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 1 }, ( short ) 0, ( short ) 1 );
    }

    private void shouldUpdateTime( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();

        byte reqValidation = Util.arrayCompare( validationTime, ( short ) 0, buffer, ( short ) ISO7816.OFFSET_CDATA, ( short ) 8 );

        isTimeOK = ( reqValidation == ( byte ) ( -1 ) ? ( byte ) 1 : ( byte ) 0 );

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ isTimeOK }, ( short ) 0, ( short ) 1 );
    }

    private void updateTime( APDU apdu )
    {
        if ( testSignature( apdu, timestampPublicKey, ( short ) 0, ( short ) 16, ( short ) 256 ) != ( byte ) 1 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 1 }, ( short ) 0, ( short ) 1 );

            return;
        }

        byte reqValidation = Util.arrayCompare( currentTime, ( short ) 0, transientInBuffer, ( short ) 0, ( short ) 8 );

        if ( reqValidation >= ( byte ) 0 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 2 }, ( short ) 0, ( short ) 1 );

            return;
        }

        Util.arrayCopy( transientInBuffer, ( short ) 0, currentTime, ( short ) 0, ( short ) 8 );
        Util.arrayCopy( transientInBuffer, ( short ) 8, validationTime, ( short ) 0, ( short ) 8 );

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 0 }, ( short ) 0, ( short ) 1 );
    }

    private short getEncodedSize()
    {
        return ( short ) ( ( short ) ( ( transientInBuffer[ 1 ] & 0xff ) << 8 ) | ( ( short ) transientInBuffer[ 0 ] & 0xff ) );
    }

    private void authenticateSP( APDU apdu )
    {
        byte isSignatureOK = testSignature( apdu, caPublicKey, ( short ) 2, getEncodedSize(), ( short ) 256 );

        if ( isSignatureOK != 1 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 1 }, ( short ) 0, ( short ) 1 );

            return;
        }

        if ( Util.arrayCompare( currentTime, ( short ) 0, transientInBuffer, ( short ) 16, ( short ) 8 ) == ( byte ) -1 ||
                Util.arrayCompare( currentTime, ( short ) 0, transientInBuffer, ( short ) 24, ( short ) 8 ) == ( byte ) 1 )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 2 }, ( short ) 0, ( short ) 1 );

            return;
        }

        // Generate random symmetric key

        aesKey = ( AESKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_AES, ( short ) 128, true );
        byte[] keyBytes = JCSystem.makeTransientByteArray( ( short ) 16, JCSystem.CLEAR_ON_RESET );

        RandomData rnd = RandomData.getInstance( RandomData.ALG_SECURE_RANDOM );
        rnd.generateData( keyBytes, ( short ) 0, ( short ) 16 );

        aesKey.setKey( keyBytes, ( short ) 0 );

        Cipher       rsaCipher     = Cipher.getInstance( Cipher.ALG_RSA_PKCS1, false );
        RSAPublicKey certPublicKey = ( RSAPublicKey ) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PUBLIC, ( short ) 2048, false );
        certPublicKey.setExponent( caExponent, ( short ) 0, ( short ) caExponent.length );
        certPublicKey.setModulus( transientInBuffer, ( short ) 35, ( short ) 256 );
        rsaCipher.init( certPublicKey, Cipher.MODE_ENCRYPT );

        byte[] encryptedKey     = JCSystem.makeTransientByteArray( ( short ) 256, JCSystem.CLEAR_ON_RESET );
        short  encryptedKeySize = rsaCipher.doFinal( keyBytes, ( short ) 0, ( short ) keyBytes.length, encryptedKey, ( short ) 0 );

        Cipher cipher = Cipher.getInstance( Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false );
        cipher.init( aesKey, Cipher.MODE_ENCRYPT );

        byte[] encryptedChallenge = JCSystem.makeTransientByteArray( ( short ) 64, JCSystem.CLEAR_ON_RESET );

        // TODO: IF TESTED, USE SECURE RANDOM
        short off = cipher.update( challenge, ( short ) 0, ( short ) 16, encryptedChallenge, ( short ) 0 );
        cipher.doFinal( transientInBuffer, ( short ) 0, ( short ) 16, encryptedChallenge, off ); //Subject

        Util.arrayCopy( encryptedKey, ( short ) 0, transientOutBuffer, ( short ) 0, encryptedKeySize );
        Util.arrayCopy( encryptedChallenge, ( short ) 0, transientOutBuffer, encryptedKeySize, ( short ) encryptedChallenge.length );

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 0 }, ( short ) 0, ( short ) 1 );
    }

    private void confirmChallenge( APDU apdu )
    {
        byte buffer[] = apdu.getBuffer();

        Cipher cipher = Cipher.getInstance( Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false );

        cipher.init( aesKey, Cipher.MODE_DECRYPT );

        byte[] decrypted = JCSystem.makeTransientByteArray( ( short ) 16, JCSystem.CLEAR_ON_RESET );

        cipher.doFinal( buffer, ( short ) ISO7816.OFFSET_CDATA, ( short ) 16, decrypted, ( short ) 0 );

        byte isOK = 1;
        for ( short i = 0; i < decrypted.length; i++ )
        {
            if ( decrypted[ i ] != ( byte ) ( challenge[ i ] + ( byte ) 1 ) )
                isOK = 0;
        }

        auth = isOK == (byte)1;

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ isOK }, ( short ) 0, ( short ) 1 );
    }

    private void authenticateCard( APDU apdu )
    {
        //TODO auth check
        byte buffer[] = apdu.getBuffer();

        Cipher cipher = Cipher.getInstance( Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false );

        cipher.init( aesKey, Cipher.MODE_DECRYPT );

        byte[] decrypted = JCSystem.makeTransientByteArray( ( short ) 16, JCSystem.CLEAR_ON_RESET );

        cipher.doFinal( buffer, ( short ) ISO7816.OFFSET_CDATA, ( short ) 16, decrypted, ( short ) 0 );

        //TODO add "auth"
        //TODO add signing
        byte[]                   digest = new byte[ 128 ];
        InitializedMessageDigest dig    = MessageDigest.getInitializedMessageDigestInstance( MessageDigest.ALG_SHA_256, false );
        dig.doFinal( decrypted, ( short ) 0, ( short ) decrypted.length, digest, ( short ) 0 );

        cipher.init( aesKey, Cipher.MODE_ENCRYPT );

        byte[] output = new byte[ 128 ];
        cipher.doFinal( digest, ( short ) 0, ( short ) 128, output, ( short ) 0 );

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) output.length );
        apdu.sendBytesLong( output, ( short ) 0, ( short ) output.length );
    }


    private byte testSignature( APDU apdu, Key key, short off, short len1, short len2 )
    {
        Signature signature = Signature.getInstance( Signature.ALG_RSA_SHA_PKCS1, false );

        signature.init( key, Signature.MODE_VERIFY );
        byte isSignatureOK = ( signature.verify( transientInBuffer, off, len1, transientInBuffer, ( short ) ( len1 + off ), len2 ) ? ( byte ) 1 : ( byte ) 0 );

        return isSignatureOK;
    }

    private void attributeQuery( APDU apdu )
    {
        byte [] buffer = apdu.getBuffer();

        if( !pin.check( buffer, ISO7816.OFFSET_CDATA, PIN_SIZE ))
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 1 }, ( short ) 0, ( short ) 1 );
            return;
        }

        if( !auth )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 2 }, ( short ) 0, ( short ) 1 );
            return;
        }

        if( !hasPermissions( transientInBuffer[(short)16], buffer[(short)(ISO7816.OFFSET_CDATA + PIN_SIZE)] ) )
        {
            apdu.setOutgoing();
            apdu.setOutgoingLength( ( short ) 1 );
            apdu.sendBytesLong( new byte[]{ 3 }, ( short ) 0, ( short ) 1 );
            return;
        }

        byte[] tempBuffer = JCSystem.makeTransientByteArray( (short)1024, JCSystem.CLEAR_ON_RESET );
        short off = fillBufferWithAttributes( tempBuffer, buffer[(short)(ISO7816.OFFSET_CDATA + PIN_SIZE)] );


        Cipher cipher = Cipher.getInstance( Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false );
        cipher.init( aesKey, Cipher.MODE_ENCRYPT );

        transientOutBuffer[(short)0] = (byte) (off & 0xFF);
        transientOutBuffer[(short)1] = (byte) ((off >> 8) & 0xFF);

        for( short i = 0; i < (short)(off / (short)16 + (short)1); i++ )
        {
            cipher.update( tempBuffer, (short)(i * (short)16), (short)16, transientOutBuffer, (short)((short)2 + i * (short)16) );
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength( ( short ) 1 );
        apdu.sendBytesLong( new byte[]{ 0 }, ( short ) 0, ( short ) 1 );
    }

    private short fillBufferWithAttributes( byte[] buffer, byte request )
    {
        short offset = 0;
        if( (byte)(request & IDENTIFIER_BIT) != (byte) 0)
        {
            InitializedMessageDigest dig    = MessageDigest.getInitializedMessageDigestInstance( MessageDigest.ALG_SHA_256, false );
            dig.update( identifier, (short)0, (short)identifier.length ); //Update with personal key K_u
            dig.doFinal( transientInBuffer, ( short ) 0, ( short ) 16, buffer, offset ); //Update with subject name

            offset = (short)(offset + identifier.length);
            offset = (short)(offset + (short)16);
        }
        if( (byte)(request & NAME_BIT) != (byte) 0)
        {
            Util.arrayCopy( name, (short)0, buffer, offset, (short) name.length );
            offset = (short)(offset + name.length);
        }
        if( (byte)(request & ADDRESS_BIT) != (byte) 0)
        {
            Util.arrayCopy( address, (short)0, buffer, offset, (short) address.length );
            offset = (short)(offset + address.length);
        }
        if( (byte)(request & COUNTRY_BIT) != (byte) 0)
        {
            Util.arrayCopy( country, (short)0, buffer, offset, (short) country.length );
            offset = (short)(offset + country.length);
        }
        if( (byte)(request & BIRTHDAY_BIT) != (byte) 0)
        {
            Util.arrayCopy( birthDay, (short)0, buffer, offset, (short) birthDay.length );
            offset = (short)(offset + birthDay.length);
        }
        if( (byte)(request & AGE_BIT) != (byte) 0)
        {
            byte[] age = new byte[1]; //TODO
            Util.arrayCopy( age, (short)0, buffer, offset, (short) age.length );
            offset = (short)(offset + birthDay.length);
        }
        if( (byte)(request & GENDER_BIT) != (byte) 0)
        {
            Util.arrayCopy( gender, (short)0, buffer, offset, (short) gender.length );
            offset = (short)(offset + gender.length);
        }
        if( (byte)(request & PICTURE_BIT) != (byte) 0)
        {
            Util.arrayCopy( picture, (short)0, buffer, offset, (short) picture.length );
            offset = (short)(offset + picture.length);
        }

        return offset;
    }

    private boolean hasPermissions( byte type, byte request )
    {
        switch ( type )
        {
            case (byte)'A':
                return (byte)(E_GOV_MASK | request) == E_GOV_MASK;
            case (byte)'B':
                return (byte)(SOC_NET_MASK | request) == SOC_NET_MASK;
            case (byte)'C':
                return (byte)(DEFAULT_MASK | request) == DEFAULT_MASK;
            default:
                return false;
        }
    }

    /*
     * This method is used to authenticate the owner of the card using a PIN code.
     */
    private void validatePIN( APDU apdu )
    {
        byte[] buffer = apdu.getBuffer();
        if ( buffer[ ISO7816.OFFSET_LC ] == PIN_SIZE )
        {
            apdu.setIncomingAndReceive();
            if ( !pin.check( buffer, ISO7816.OFFSET_CDATA, PIN_SIZE ) )
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
