package be.msec;

import be.msec.smartcard.IdentityCard;
import be.msec.timestamp.SignedTimestamp;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import sun.security.x509.X509CertInfo;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import java.util.Date;

public class Controller
{
    @FXML
    private Button pinButton;

    @FXML
    private TextArea logPanel;

    @FXML
    private PasswordField pinField;

    private Simulator simulator;

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

        commandAPDU = new CommandAPDU( 0x80, 0x50, 0x00, 0x00 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );

        byte[] data = response.getData();

        SecretKey key = new SecretKeySpec( data, 0,16,  "AES" );
        byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec spec = new IvParameterSpec( ivdata );

        try
        {
            Cipher cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
            cipher.init( Cipher.DECRYPT_MODE, key, spec );

            byte result [] = cipher.doFinal( data, 16, data.length - 16 );

            for( int i = 0; i < result.length; i++ )
                result[i] += (byte)1;

            Cipher encryptCypher = Cipher.getInstance( "AES/CBC/NoPadding" );
            encryptCypher.init( Cipher.ENCRYPT_MODE, key, spec );
            byte newChallenge[] = encryptCypher.doFinal( result,0, 16 );

            commandAPDU = new CommandAPDU( 0x80, 0x51, 0x00, 0x00, newChallenge, 0, 16 );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            System.out.println( Arrays.toString( result ) );
        }
        catch ( NoSuchAlgorithmException e )
        {
            e.printStackTrace();
        }
        catch ( NoSuchPaddingException e )
        {
            e.printStackTrace();
        }
        catch ( InvalidKeyException e )
        {
            e.printStackTrace();
        }
        catch ( BadPaddingException e )
        {
            e.printStackTrace();
        }
        catch ( IllegalBlockSizeException e )
        {
            e.printStackTrace();
        }
        catch ( InvalidAlgorithmParameterException e )
        {
            e.printStackTrace();
        }

        commandAPDU = new CommandAPDU( 0x80, 0x22, 0x00, 0x00, new byte[]{ 0x01, 0x02, 0x03, 0x04 } );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );

        commandAPDU = new CommandAPDU( 0x80, 0x24, 0x00, 0x00 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );

        write( new BigInteger( 1, response.getData() ).toString( 16 ) );

        SignedTimestamp now  = getTimestampFromRemote();
        byte[] time = now.getTimestamp();

        System.out.println( Arrays.toString( time ) );

        commandAPDU = new CommandAPDU( 0x80, 0x26, 0x00, 0x00, time );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( response.toString() );
        write( Arrays.toString( response.getData() ) );

        byte [] buffer = new byte[ 8 + now.getSignature().length ];
        for(int i = 0; i < 8; i++ )
            buffer[i] = time[i];
        for(int i = 0; i < now.getSignature().length; i++ )
            buffer[i + 8] = now.getSignature()[i];
        //byte [] buffer = new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 97, -99, -27, 77, 41, -55, -23, -39, 119, -97, 43, -30, -46, 109, -41, 1, 39, 126, -88, 79, -39, 7, 113, -81, -8, -72, 81, 48, 86, -6, -52, 113, -54, -88, -97, 120, 110, -101, 8, -60, 9, 15, 103, -75, -126, 125, -43, 81, -75, 73, 12, 106, -36, -30, -34, -34, 96, 27, 106, -83, 100, 107, -39, -120, 79, 25, -32, 101, 83, -34, 32, 19, -84, 35, -41, -42, 120, -73, -126, -8, 117, -121, -37, -91, 56, 20, -109, -64, 63, -33, 40, 35, -75, 72, -64, 109, -9, -23, 68, -18, 113, -126, 63, -121, 9, -61, 26, -115, -54, -95, -42, -122, 113, 30, 63, -62, -33, -105, -101, 8, -68, -101, 123, -28, -107, -5, -90, 86, 114, 63, -37, 120, -64, -36, 57, -41, 116, -88, 40, 105, 64, -76, 40, 25, -37, 52, 23, 120, -83, -40, 37, 5, 53, 36, -15, 105, -58, 116, -44, -54, -101, 126, 52, -5, 70, 102, 33, 13, 123, -49, 107, 98, -31, 78, -70, 41, -85, 40, -115, 84, -13, 19, -4, -73, -84, 104, -14, -112, -49, 20, 55, -1, -93, 107, 15, -66, -3, -110, 105, -71, 125, 84, -35, -104, 27, 100, 106, -112, 67, 84, 52, 38, -123, 88, 69, -95, -82, -25, -27, -67, -47, -78, -26, -6, -107, -85, 99, -54, 108, 54, 64, -60, 25, -30, -1, 7, 6, -54, -9, 60, 7, 74, -19, 63, 17, 58, 21, -115, 93, 58, 46, 67, 91, 39, 115, 27 };

        updateTransientBuffer( buffer );

        write( "Updating and verifying signed timestamp" );

        commandAPDU = new CommandAPDU( 0x80, 0x27, 0x00, 0x00  );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( "Correct signature: " + (response.getData()[0] == 0) );

    }

    private void updateTransientBuffer( byte[] buffer )
    {
        write( "Clearing transient buffer" );
        // Clear buffer
        CommandAPDU commandAPDU = new CommandAPDU( 0x80, 0x30, 0x00, 0x00 );
        ResponseAPDU response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( "Buffer clear, filling with new data" );

        int iterations = 0;
        for( int i = 0; i < (buffer.length / 240); i++ )
        {
            byte [] currentBuffer = new byte[241];

            currentBuffer[0] = (byte)240;
            for(int j = 0; j < 240; j++ )
                currentBuffer[ j  + 1 ] = buffer[i * 240 + j];

            commandAPDU = new CommandAPDU( 0x80, 0x31, 0x00, 0x00, currentBuffer );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            iterations++;
        }

        int sizeLeft = buffer.length - iterations * 240;
        if( sizeLeft > 0 )
        {
            byte [] currentBuffer = new byte[sizeLeft + 1];

            currentBuffer[0] = (byte)sizeLeft;
            for(int j = 0; j < sizeLeft; j++ )
                currentBuffer[ j + 1 ] = buffer[iterations * 240 + j];

            commandAPDU = new CommandAPDU( 0x80, 0x31, 0x00, 0x00, currentBuffer );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );
        }

        write( "Buffer ready" );

        X509CertInfo info;
    }


    private SignedTimestamp getTimestampFromRemote()
    {
        SignedTimestamp timestamp = null;

        try
        {
            SSLContext context = SSLUtil.createClientSSLContext( "CA.jks", "password" );

            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket( "127.0.0.1", 1207 );
            //socket.setEnabledCipherSuites( enabledCipherSuites );

            Arrays.stream( socket.getEnabledCipherSuites() ).forEach( System.out::println );
            ObjectInputStream inputStream = new ObjectInputStream( socket.getInputStream() );

            timestamp = (SignedTimestamp ) inputStream.readObject();

            inputStream.close();
            socket.close();


        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }

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
