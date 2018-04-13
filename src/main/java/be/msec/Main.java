package be.msec;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

/**
 * @author Pieter
 * @version 1.0
 */
public class Main extends Application
{
    private static final char[] passphrase = "password".toCharArray();

    public static void main( String[] args )
    {
        boolean PRINT_SHITTY_KEY = true;

        if ( PRINT_SHITTY_KEY )
        {
            try
            {
                //TODO: this is for anton
                SSLUtil.createKeyStore( "TIME_keys.jks", "password" );


                //RSAPublicKey key = (RSAPublicKey ) SSLUtil.getPublicKey();
                //System.out.println( Arrays.toString( key.getPublicExponent().toByteArray() ) );
                //System.out.println( Arrays.toString( key.getModulus().toByteArray() ) );

                //System.out.println( key.getModulus().toByteArray().length );

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

                SSLUtil.createKeyStore( "CA.jks", "password" );

                PublicKey publicKey = SSLUtil.getPublicKey();

                Signature signature = Signature.getInstance( "SHA1withRSA" );
                signature.initVerify( publicKey );
                signature.update( info );
                System.out.println( signature.verify( sign ) );
                //System.out.println( Arrays.toString( signature.sign() ) );
                //System.out.println( signature.sign().length );
            }
            catch ( KeyStoreException e )
            {
                e.printStackTrace();
            }
            catch ( IOException e )
            {
                e.printStackTrace();
            }
            catch ( CertificateException e )
            {
                e.printStackTrace();
            }
            catch ( NoSuchAlgorithmException e )
            {
                e.printStackTrace();
            }
            catch ( SignatureException e )
            {
                e.printStackTrace();
            }
            catch ( InvalidKeyException e )
            {
                e.printStackTrace();
            }
        }
        else
        {
            Application.launch( Main.class, args );
        }

    }

    public static byte[] getPublicKey( byte[] input, short length )
    {
        byte[] output = new byte[length];

        for (short i = 0; i < length; i++)
        {
            output[i] = input[input.length - length + i];
        }

        return output;
    }

    public static byte[] getSubjectName( byte[] input, short keyLength )
    {
        short count = 0;
        short start = (short) (input.length - keyLength);
        while ( count++ != input[--start] ) ;
        byte[] output = new byte[count - 1];
        for (short i = 0; i < count - 1; i++)
        {
            output[i] = input[start + i + 1];
        }

        return output;
    }


    public static byte[] getValidAfterTime( byte[] input )
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

    public static byte[] getValidBeforeTime( byte[] input )
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

    public static boolean compareTime( byte[] start, byte[] now, byte[] end )
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

    @Override
    public void start( Stage stage ) throws Exception
    {
        Parent root = FXMLLoader.load( getClass().getResource( "/scene.fxml" ) );
        stage.setTitle( "Middleware" );
        stage.setScene( new Scene( root ) );
        stage.show();
    }
}
