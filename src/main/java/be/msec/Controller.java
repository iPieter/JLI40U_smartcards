package be.msec;

import be.msec.SP.ByteArray;
import be.msec.smartcard.IdentityCard;
import be.msec.timestamp.SignedTimestamp;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextInputDialog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

public class Controller implements Runnable
{
    private static final Logger LOGGER = LoggerFactory.getLogger( Controller.class );

    @FXML
    private Button updateButton;

    @FXML
    private TextArea logPanel;

    private Simulator simulator;

    private SSLClient serviceProvider;

    public Controller()
    {
    }

    @FXML
    public void initialize()
    {
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
        for ( int i = 0; i < time.length; i++ )
            buffer[ i ] = time[ i ];
        for ( int i = 0; i < now.getSignature().length; i++ )
            buffer[ i + time.length ] = now.getSignature()[ i ];

        updateTransientBuffer( buffer );

        write( "Updating and verifying signed timestamp" );

        commandAPDU = new CommandAPDU( 0x80, 0x27, 0x00, 0x00 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        System.out.println( Arrays.toString( response.getData() ) );

        write( "Correct signature: " + ( response.getData()[ 0 ] == 0 ) + " statuscode: " + response.getData()[ 0 ] );

        write( "===============================================================" );
    }

    private void receiveCertificate()
    {
        write( "Step 2: sending challenge" );
        write( "Uploading ServiceProvider certificate" );
        byte[]  result = ( ( ByteArray ) serviceProvider.receiveObject() ).getChallenge();
        updateTransientBuffer( result );
    }

    private void exchangeChallenges( )
    {
        LOGGER.info( "Exchanging challenges" );

        byte[]       buffer;
        CommandAPDU  commandAPDU;
        ResponseAPDU response;

        commandAPDU = new CommandAPDU( 0x80, 0x50, 0x00, 0x00 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );

        byte[] responseBuffer = new byte[ 1024 ];

        for ( int i = 0; i < 4; i++ )
        {
            commandAPDU = new CommandAPDU( 0x80, 0x32, 0x00, 0x00, new byte[]{ ( byte ) i } );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            for ( int j = 0; j < response.getData().length; j++ )
                responseBuffer[ i * 240 + j ] = response.getData()[ j ];
        }

        serviceProvider.writeObject( new ByteArray( responseBuffer ) );

        ByteArray byteArray = ( ByteArray ) serviceProvider.receiveObject();

        write( "Received challenge response" );

        commandAPDU = new CommandAPDU( 0x80, 0x51, 0x00, 0x00, byteArray.getChallenge(), 0, 16 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );
        write( "Validation challenge: " + response.getData()[ 0 ] );

        write( "===============================================================" );

        // STEP 3 ----------
        byteArray = ( ByteArray ) serviceProvider.receiveObject();

        write( "Step 3: received challenge" );
        commandAPDU = new CommandAPDU( 0x80, 0x60, 0x00, 0x00, byteArray.getChallenge(), 0, 16 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( Arrays.toString(  response.getData() ) );

        byte[] output = readTransientBuffer();

        serviceProvider.writeObject( new ByteArray( output ) );

        write( "Sent response to challenge." );

    }

    ByteArray mask;
    private void listenForRequests()
    {
        try
        {
            write( "===============================================================" );
            mask = ( ByteArray ) serviceProvider.receiveObject();
            write( "Received a request" );
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

    private void exchangeAttributes()
    {
        Platform.runLater( () -> {
            byte[]       buffer;
            CommandAPDU  commandAPDU;
            ResponseAPDU response;

            write( "Received the following request: " + mask.getChallenge()[ 0 ] );

            Optional<String> result = getPin( mask.getChallenge()[0] );

            if( result.isPresent() )
            {
                int pin = Integer.parseInt( result.get() );

                int i4 = pin - (pin / 10) * 10;
                pin /= 10;
                int i3 = pin - (pin / 10) * 10;
                pin /= 10;
                int i2 = pin - (pin / 10) * 10;
                pin /= 10;
                int i1 = pin - (pin / 10) * 10;

                write( "PIN: " + i1 + "," + i2 + "," + i3 + "," + i4  );

                commandAPDU = new CommandAPDU( 0x80, 0x70, 0x00, 0x00, new byte[]{ (byte)i1,(byte)i2,(byte)i3,(byte)i4, mask.getChallenge()[ 0 ] } );
                response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );
                System.out.println( Arrays.toString( response.getData() ) );


                if ( response.getData()[ 0 ] == 0x00 )
                {
                    byte[] personalInformation = readTransientBuffer();
                    int size = getEncodedSize( personalInformation );
                    byte[] shortened = Arrays.copyOfRange( personalInformation, 0, 16 * ( size / 16 + 1 ) + 2 );
                    System.out.println( Arrays.toString( personalInformation ) );
                    serviceProvider.writeObject( new ByteArray( shortened ) );
                }
                else
                {
                    serviceProvider.writeObject( new ByteArray( new byte[ 0 ] ) );
                }
            }
            else
            {
                serviceProvider.writeObject( new ByteArray( new byte[ 0 ] ) );
            }

            runLoop();
        } );
    }

    public void runLoop()
    {
        new Thread( () -> {
            listenForRequests();
            exchangeAttributes();
        }).start();
    }

    public void run()
    {
        System.out.println( "Connecting to SP" );
        serviceProvider = new SSLClient( "127.0.0.1", 1271 );

        new Thread( () -> {
            receiveCertificate();
            exchangeChallenges();
            listenForRequests();
            exchangeAttributes();
        }).start();
    }

    private Optional<String> getPin( byte request )
    {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle( "Enter PIN code" );

        String requestedInfo = "Requested info: \n";

        byte IDENTIFIER_BIT = ( byte ) ( 1 << 7 );
        byte NAME_BIT       = ( byte ) ( 1 << 6 );
        byte ADDRESS_BIT    = ( byte ) ( 1 << 5 );
        byte COUNTRY_BIT    = ( byte ) ( 1 << 4 );
        byte BIRTHDAY_BIT   = ( byte ) ( 1 << 3 );
        byte AGE_BIT        = ( byte ) ( 1 << 2 );
        byte GENDER_BIT     = ( byte ) ( 1 << 1 );
        byte PICTURE_BIT    = ( byte ) ( 1 << 0 );
        requestedInfo += ( byte ) ( request & IDENTIFIER_BIT ) != ( byte ) 0 ? "Identifier," : "";
        requestedInfo += ( byte ) ( request & NAME_BIT ) != ( byte ) 0 ? "Name," : "";
        requestedInfo += ( byte ) ( request & ADDRESS_BIT ) != ( byte ) 0 ? "Address," : "";
        requestedInfo += ( byte ) ( request & COUNTRY_BIT ) != ( byte ) 0 ? "Country," : "";
        requestedInfo += ( byte ) ( request & BIRTHDAY_BIT ) != ( byte ) 0 ? "Birthday," : "";
        requestedInfo += ( byte ) ( request & AGE_BIT ) != ( byte ) 0 ? "Age," : "";
        requestedInfo += ( byte ) ( request & GENDER_BIT ) != ( byte ) 0 ? "Gender," : "";
        requestedInfo += ( byte ) ( request & PICTURE_BIT ) != ( byte ) 0 ? "Picture" : "";
        dialog.setHeaderText( requestedInfo );

        Optional <String> result = dialog.showAndWait();

        while ( result.isPresent() && !result.get().matches( "\\d{4}" ) )
        {
            result = dialog.showAndWait();
        }

        return result;
    }

    private void updateTransientBuffer( byte[] buffer )
    {
        write( "Clearing transient buffer" );
        // Clear buffer
        CommandAPDU  commandAPDU = new CommandAPDU( 0x80, 0x30, 0x00, 0x00 );
        ResponseAPDU response    = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( "Buffer clear, filling with new data" );

        int iterations = 0;
        for ( int i = 0; i < ( buffer.length / 240 ); i++ )
        {
            byte[] currentBuffer = new byte[ 241 ];

            currentBuffer[ 0 ] = ( byte ) 240;
            for ( int j = 0; j < 240; j++ )
                currentBuffer[ j + 1 ] = buffer[ i * 240 + j ];

            commandAPDU = new CommandAPDU( 0x80, 0x31, 0x00, 0x00, currentBuffer );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            iterations++;
        }

        int sizeLeft = buffer.length - iterations * 240;
        if ( sizeLeft > 0 )
        {
            byte[] currentBuffer = new byte[ sizeLeft + 1 ];

            currentBuffer[ 0 ] = ( byte ) sizeLeft;
            for ( int j = 0; j < sizeLeft; j++ )
                currentBuffer[ j + 1 ] = buffer[ iterations * 240 + j ];

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
    public byte[] readTransientBuffer()
    {
        byte[] responseBuffer = new byte[ 1024 ];

        for ( int i = 0; i < 4; i++ )
        {
            CommandAPDU  commandAPDU = new CommandAPDU( 0x80, 0x32, 0x00, 0x00, new byte[]{ ( byte ) i } );
            ResponseAPDU response    = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            for ( int j = 0; j < response.getData().length; j++ )
                responseBuffer[ i * 240 + j ] = response.getData()[ j ];
        }

        return responseBuffer;
    }

    private short getEncodedSize( byte[] buffer )
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

        SignedTimestamp timestamp = ( SignedTimestamp ) timestampClient.receiveObject();
        LOGGER.info( "Received object: " + timestamp );

        LOGGER.info( "Closing connection" );
        timestampClient.close();

        return timestamp;
    }

    private void write( String text )
    {
        Platform.runLater( () -> logPanel.appendText( text + " \n" ) );
    }

    public void login()
    {
        logPanel.appendText( "Logging in \n" );
    }
}
