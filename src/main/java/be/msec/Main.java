package be.msec;

import be.msec.SP.Card;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * @author Pieter
 * @version 1.0
 */
public class Main extends Application
{
    private static SSLSocket        socket    = null;
    private static Thread           thread    = null;
    private static DataInputStream  console   = null;
    private static DataOutputStream streamOut = null;

    private static final char[] passphrase = "password".toCharArray();

    public static void main( String[] args )
    {
        boolean PRINT_SHITTY_KEY = false;

        if ( PRINT_SHITTY_KEY )
        {
            try
            {
                SSLContext context = SSLUtil.createClientSSLContext( "CA.jks", "password" );

                //socket = (SSLSocket) context.getSocketFactory().createSocket( "127.0.0.1", 1271 );
                //socket.setEnabledCipherSuites( enabledCipherSuites );

                //Arrays.stream( socket.getEnabledCipherSuites() ).forEach( System.out::println );

                /*
                ObjectOutputStream os = new ObjectOutputStream( socket.getOutputStream() );
                ObjectInputStream  is = new ObjectInputStream( socket.getInputStream() );

                os.writeObject( new Card( "bob" ) );
                System.out.println("wrote card to ssl stream");

                Certificate certificate = (Certificate) is.readObject();

                System.out.println(certificate.toString());
                os.close();
                is.close();
                socket.close();
                */

                FileInputStream fis         = new FileInputStream( "vincentje.jpeg" );
                int              currentByte = 0;
                int              idx         = 0;
                byte[]           tmp         = new byte[1000];

                while ( (currentByte = fis.read()) != -1 )
                    tmp[idx++] = (byte)currentByte;

                byte[] buffer = new byte[ idx + 2 ];

                int certSize = idx - 256;

                buffer[0] = (byte)(idx & 0xFF );
                buffer[1] = (byte)((idx >> 8) & 0xFF );

                for( int i = 0; i < idx; i++ )
                    buffer[i + 2] = tmp[i];

                System.out.println( Arrays.toString( buffer ) );
                System.out.println( buffer.length );
                SSLUtil.createKeyStore( "SMARTCARD_keys.jks", "password" );


                RSAPublicKey  key = (RSAPublicKey ) SSLUtil.getPublicKey( "SMARTCARD" );
                RSAPrivateKey privateKey =  (RSAPrivateKey ) SSLUtil.getPrivateKey( "SMARTCARD" );

                System.out.println( Arrays.toString( privateKey.getPrivateExponent().toByteArray() ) );
                System.out.println( Arrays.toString( privateKey.getModulus().toByteArray() ) );

                System.out.println( Arrays.toString( key.getPublicExponent().toByteArray() ) );
                System.out.println( Arrays.toString( key.getModulus().toByteArray() ) );

                System.out.println( key.getModulus().toByteArray().length );


                System.out.println( "---info---" );
                byte[] info = SSLUtil.getInfo( "time" );
                System.out.println( Arrays.toString( info ) );
                System.out.println( "---signature---" );
                byte[] sign = SSLUtil.getCertificate( "time" ).getSignature();
                System.out.println( Arrays.toString( sign ) );
                System.out.println( "---key---" );
                System.out.println( Arrays.toString( SSLUtil.getCertificate( "time" ).getPublicKey().getEncoded() ) );
                System.out.println( "---name---" );
                System.out.println( Arrays.toString( "time".getBytes() ) );
                System.out.println( Arrays.toString( "CN=TIME".getBytes() ) );
                System.out.println( Arrays.toString( "CN=ROOT".getBytes() ) );
                System.out.println( Arrays.toString( "20180412090056".getBytes() ) );
                System.out.println( Arrays.toString( "20180513090056".getBytes() ) );
                System.out.println( Arrays.toString( ByteBuffer.allocate( Long.SIZE / Byte.SIZE ).putLong( 1526202056000L ).array() ) );


                //System.out.println( Arrays.toString( signature.sign() ) );
                //System.out.println( signature.sign().length );
            }
            catch ( Exception e )
            {
                e.printStackTrace();
            }

        }
        else
        {
            Application.launch( Main.class, args );
        }

    }

    @Override
    public void start( Stage stage ) throws Exception
    {
        Parent root = FXMLLoader.load( getClass().getResource( "/scene.fxml" ) );
        stage.setTitle( "Middleware" );
        stage.setScene( new Scene( root ) );
        stage.show();
    }
}
