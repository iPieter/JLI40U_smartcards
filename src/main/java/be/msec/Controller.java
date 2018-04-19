package be.msec;

import be.msec.SP.ByteArray;
import be.msec.smartcard.IdentityCard;
import be.msec.timestamp.SignedTimestamp;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;
import java.util.Collections;

public class Controller
{
    private static final Logger LOGGER = LoggerFactory.getLogger( Controller.class );

    @FXML
    private Button pinButton;

    @FXML
    private TextArea logPanel;

    @FXML
    private PasswordField pinField;

    private Simulator simulator;

    private SSLClient serviceProvider;

    public Controller()
    {
    }

    @FXML
    public void initialize()
    {
        serviceProvider = new SSLClient( "127.0.0.1", 1271 );

        simulator = new Simulator();

        AID appletAID = AIDUtil.create( "F000000001" );
        simulator.installApplet( appletAID, IdentityCard.class );

        simulator.selectApplet( appletAID );

        write( "Simulator loaded." );

        CommandAPDU  commandAPDU;
        ResponseAPDU response;
        byte[]       buffer;


        SignedTimestamp now  = getTimestampFromRemote();
        byte[]          time = now.getTimestamp();

        write( "Time from server: " + Arrays.toString( time ) );

        write( "Testing time" );

        commandAPDU = new CommandAPDU( 0x80, 0x26, 0x00, 0x00, time );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( "Time needs update = " + Arrays.toString( response.getData() ) );

        buffer = new byte[ time.length + now.getSignature().length ];
        for(int i = 0; i < time.length; i++ )
            buffer[i] = time[i];
        for(int i = 0; i < now.getSignature().length; i++ )
            buffer[i + time.length] = now.getSignature()[i];

        updateTransientBuffer( buffer );

        write( "Updating and verifying signed timestamp" );

        commandAPDU = new CommandAPDU( 0x80, 0x27, 0x00, 0x00  );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        System.out.println( Arrays.toString(response.getData()));

        write( "Correct signature: " + (response.getData()[0] == 0) + " statuscode:" + response.getData()[0] );


        write( "Uploading certificate" );

        try
        {

            /*
            X509CertImpl cert = (X509CertImpl) serviceProvider.receiveObject();

            SSLUtil.createKeyStore( "GOV1_keys.jks", "password" );
            X509CertImpl cert =  SSLUtil.getCertificate( "GOV1" );
            byte[] signature = cert.getSignature();
            byte[] certEncoded = SSLUtil.getInfo( "GOV1" );

            buffer = new byte[ signature.length + certEncoded.length + 2 ];

            buffer[0] = (byte)(certEncoded.length & 0xFF );
            buffer[1] = (byte)((certEncoded.length >> 8) & 0xFF );

            for( int i = 0; i < certEncoded.length; i++ )
                buffer[i + 2] = certEncoded[i];

            for( int i = 0; i < signature.length; i++ )
                buffer[i + certEncoded.length + 2] = signature[i];
            */

            //receive certificate in compact form
            buffer = ((ByteArray) serviceProvider.receiveObject()).getChallenge();

            updateTransientBuffer( buffer );

        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }

        commandAPDU = new CommandAPDU( 0x80, 0x50, 0x00, 0x00 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );

        byte[] responseBuffer = new byte[1024];

        for (int i = 0; i < 4; i++)
        {
            commandAPDU = new CommandAPDU( 0x80, 0x32, 0x00, 0x00, new byte[]{ (byte) i } );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            for (int j = 0; j < response.getData().length; j++)
                responseBuffer[i * 240 + j] = response.getData()[j];
        }

        try
        {
            // STEP 2 ----------

            write( "Step 2: sending challenge" );

            serviceProvider.writeObject( new ByteArray( responseBuffer ) );

            /*
            Cipher        rsaCipher  = Cipher.getInstance( "RSA/ECB/PKCS1PADDING" );
            RSAPrivateKey privateKey = (RSAPrivateKey) SSLUtil.getPrivateKey( "GOV1" );

            Cipher rsaCipher = Cipher.getInstance( "RSA/ECB/PKCS1PADDING" );
            RSAPrivateKey privateKey = (RSAPrivateKey ) SSLUtil.getPrivateKey( "CUSTOM1" );
            rsaCipher.init( Cipher.DECRYPT_MODE, privateKey );



            rsaCipher.init( Cipher.DECRYPT_MODE, privateKey );

            byte[] symmKey = rsaCipher.doFinal( responseBuffer, 0, 256 );

            System.out.println( Arrays.toString( symmKey ) );

            SecretKey       key    = new SecretKeySpec( symmKey, 0, 16, "AES" );
            byte[]          ivdata = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec spec   = new IvParameterSpec( ivdata );
            Cipher          cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
            cipher.init( Cipher.DECRYPT_MODE, key, spec );

            byte result[] = cipher.doFinal( responseBuffer, 256, 32 );

            for (int i = 0; i < result.length; i++)
                result[i] += (byte) 1;

            Cipher encryptCypher = Cipher.getInstance( "AES/CBC/NoPadding" );
            encryptCypher.init( Cipher.ENCRYPT_MODE, key, spec );
            byte newChallenge[] = encryptCypher.doFinal( result, 0, 16 );
            */

            ByteArray byteArray = (ByteArray) serviceProvider.receiveObject();

            write( "Received challenge response" );

            commandAPDU = new CommandAPDU( 0x80, 0x51, 0x00, 0x00, byteArray.getChallenge(), 0, 16 );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            write( response.toString() );
            write( "Validation challenge: " + response.getData()[0] );

            // STEP 3 ----------
            byteArray = (ByteArray) serviceProvider.receiveObject();

            write( "Step 3: received challenge" );
            commandAPDU = new CommandAPDU( 0x80, 0x60, 0x00, 0x00, byteArray.getChallenge(), 0, 16 );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            System.out.println( Arrays.toString(response.getData()));

            serviceProvider.writeObject( new ByteArray( response.getData() ) );

            write("Sent response to challenge.");
            /*
            write( Arrays.toString( result ) );
            System.out.println( Arrays.toString( result ) );
            System.out.println( Arrays.toString( response.getData() ) );
            */

            //STEP 4 until the world ends
            while ( serviceProvider.isAvailiable() )
            {
                ByteArray mask = (ByteArray) serviceProvider.receiveObject();

                commandAPDU = new CommandAPDU( 0x80, 0x70, 0x00, 0x00, new byte[]{ 0x01, 0x02, 0x03, 0x04, mask.getChallenge()[0]} );
                response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );
                System.out.println(Arrays.toString( response.getData()));

                //TODO
                //1 wrong pin
                //2 not authenticated
                //3 no permission
                if ( response.getData()[0] == 0x00) {
                    byte[] personalInformation = readTransientBuffier();
                    System.out.println( Arrays.toString(personalInformation));
                    serviceProvider.writeObject( new ByteArray( personalInformation ) );
                } else
                {
                    serviceProvider.writeObject( new ByteArray( new byte[0] ) );
                }



            }
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }

        /*
        commandAPDU = new CommandAPDU( 0x80, 0x22, 0x00, 0x00, new byte[]{ 0x01, 0x02, 0x03, 0x04 } );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );

        commandAPDU = new CommandAPDU( 0x80, 0x24, 0x00, 0x00 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );

        write( new BigInteger( 1, response.getData() ).toString( 16 ) );
        */
    }

    private void updateTransientBuffer( byte[] buffer )
    {
        write( "Clearing transient buffer" );
        // Clear buffer
        CommandAPDU  commandAPDU = new CommandAPDU( 0x80, 0x30, 0x00, 0x00 );
        ResponseAPDU response    = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( "Buffer clear, filling with new data" );

        int iterations = 0;
        for (int i = 0; i < (buffer.length / 240); i++)
        {
            byte[] currentBuffer = new byte[241];

            currentBuffer[0] = (byte) 240;
            for (int j = 0; j < 240; j++)
                currentBuffer[j + 1] = buffer[i * 240 + j];

            commandAPDU = new CommandAPDU( 0x80, 0x31, 0x00, 0x00, currentBuffer );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            iterations++;
        }

        int sizeLeft = buffer.length - iterations * 240;
        if ( sizeLeft > 0 )
        {
            byte[] currentBuffer = new byte[sizeLeft + 1];

            currentBuffer[0] = (byte) sizeLeft;
            for (int j = 0; j < sizeLeft; j++)
                currentBuffer[j + 1] = buffer[iterations * 240 + j];

            commandAPDU = new CommandAPDU( 0x80, 0x31, 0x00, 0x00, currentBuffer );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );
        }

        write( "Buffer ready" );

    }

    /**
     * Reads the data on the transient buffer of the smart card
     *
     * @return A byte array with all the data.
     */
    public byte[] readTransientBuffier()
    {
        byte[] responseBuffer = new byte[1024];

        for (int i = 0; i < 4; i++)
        {
            CommandAPDU commandAPDU = new CommandAPDU( 0x80, 0x32, 0x00, 0x00, new byte[]{ (byte) i } );
            ResponseAPDU response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            for (int j = 0; j < response.getData().length; j++)
                responseBuffer[i * 240 + j] = response.getData()[j];
        }

        int size = getEncodedSize( responseBuffer );

        byte[] shortened = Arrays.copyOfRange(responseBuffer, 2, 16 * (size / 16 + 1) + 2 );

        return shortened;
    }

    private short getEncodedSize(byte[] buffer)
    {
        return ( short ) ( ( short ) ( ( buffer[ 1 ] & 0xff ) << 8 ) | ( ( short ) buffer[ 0 ] & 0xff ) );
    }


    /**
     * Creates a {@link SSLClient} and establishes a connection, fetches the timestamp and returns it.
     * <p>
     * The connection is closed afterwards.
     *
     * @return A {@link SignedTimestamp} object from the remote server.
     */
    private SignedTimestamp getTimestampFromRemote()
    {
        LOGGER.info( "Connecting to server" );
        SSLClient timestampClient = new SSLClient( "127.0.0.1", 1207 );
        LOGGER.info( "Connected, fetching timestamp" );

        SignedTimestamp timestamp = (SignedTimestamp) timestampClient.receiveObject();
        LOGGER.info( "Received object: " + timestamp );

        LOGGER.info( "Closing connection" );
        timestampClient.close();

        return timestamp;
    }

    private void write( String text )
    {
        logPanel.appendText( text + " \n" );
    }

    public void login()
    {
        logPanel.appendText( "Logging in \n" );
    }
}
