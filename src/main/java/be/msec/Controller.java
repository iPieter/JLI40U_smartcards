package be.msec;

import be.msec.smartcard.IdentityCard;
import be.msec.timestamp.SignedTimestamp;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import sun.security.x509.X509CertImpl;
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
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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

        write( "Uploading certificate" );

        try
        {
            SSLUtil.createKeyStore( "TIME_keys.jks", "password" );
            X509CertImpl cert =  SSLUtil.getCertificate( "TIME" );
            byte[] signature = cert.getSignature();
            byte[] certEncoded = SSLUtil.getInfo( "TIME" );

            byte[] buffer = new byte[ signature.length + certEncoded.length + 2 ];

            buffer[0] = (byte)(certEncoded.length & 0xFF );
            buffer[1] = (byte)((certEncoded.length >> 8) & 0xFF );

            for( int i = 0; i < certEncoded.length; i++ )
                buffer[i + 2] = certEncoded[i];

            for( int i = 0; i < signature.length; i++ )
                buffer[i + certEncoded.length + 2] = signature[i];

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

        for( int i = 0; i < 4; i++ )
        {
            commandAPDU = new CommandAPDU( 0x80, 0x32, 0x00, 0x00, new byte[]{ (byte)i } );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            for( int j = 0; j < response.getData().length; j++ )
                responseBuffer[ i * 240 + j ] = response.getData()[j];
        }

        try
        {

            Cipher rsaCipher = Cipher.getInstance( "RSA/ECB/PKCS1PADDING" );
            RSAPrivateKey privateKey = (RSAPrivateKey ) SSLUtil.getPrivateKey();
            rsaCipher.init( Cipher.DECRYPT_MODE, privateKey );

            RSAPublicKey publicKey = (RSAPublicKey ) SSLUtil.getPublicKey( "TIME" );
            byte[] mod = publicKey.getModulus().toByteArray();

            byte[] symmKey =  rsaCipher.doFinal( responseBuffer, 0, 256 );

            System.out.println( Arrays.toString( symmKey ) );

            SecretKey key = new SecretKeySpec( symmKey, 0,16,  "AES" );
            byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec spec = new IvParameterSpec( ivdata );
            Cipher cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
            cipher.init( Cipher.DECRYPT_MODE, key, spec );

            byte result [] = cipher.doFinal( responseBuffer, 256, 32 );

            for( int i = 0; i < result.length; i++ )
                result[i] += (byte)1;

            Cipher encryptCypher = Cipher.getInstance( "AES/CBC/NoPadding" );
            encryptCypher.init( Cipher.ENCRYPT_MODE, key, spec );
            byte newChallenge[] = encryptCypher.doFinal( result,0, 16 );

            commandAPDU = new CommandAPDU( 0x80, 0x51, 0x00, 0x00, newChallenge, 0, 16 );
            response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

            System.out.println( Arrays.toString( result ) );
            System.out.println( Arrays.toString( response.getData() ) );
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

        SignedTimestamp now  = getTimestampFromRemote();
        byte[] time = now.getTimestamp();

        write( "Time from server: " +  Arrays.toString( time ) );

        write( "Testing time" );

        commandAPDU = new CommandAPDU( 0x80, 0x26, 0x00, 0x00, time );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( "Time needs update = " + Arrays.toString( response.getData() ) );

        byte [] buffer = new byte[ time.length + now.getSignature().length ];
        for(int i = 0; i < time.length; i++ )
            buffer[i] = time[i];
        for(int i = 0; i < now.getSignature().length; i++ )
            buffer[i + time.length] = now.getSignature()[i];

        updateTransientBuffer( buffer );

        write( "Updating and verifying signed timestamp" );

        commandAPDU = new CommandAPDU( 0x80, 0x27, 0x00, 0x00  );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        write( "Correct signature: " + (response.getData()[0] == 0) + " statuscode:" + response.getData()[0] );

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
