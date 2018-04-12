package be.msec;

import be.msec.smartcard.HelloWorldApplet;
import be.msec.smartcard.IdentityCard;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.framework.Util;
import javafx.application.Application;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.stage.Stage;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
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
        boolean PRINT_SHITTY_KEY = true;

        if( PRINT_SHITTY_KEY )
        {
            try
            {
                SSLContext context = SSLUtil.createClientSSLContext( "CA.jks", "password" );

                socket = (SSLSocket) context.getSocketFactory().createSocket( "127.0.0.1", 1207 );
                //socket.setEnabledCipherSuites( enabledCipherSuites );

                Arrays.stream( socket.getEnabledCipherSuites() ).forEach( System.out::println );
                ObjectInputStream inputStream = new ObjectInputStream( socket.getInputStream() );

                System.out.println(inputStream.readObject());



                inputStream.close();
                socket.close();

                SSLUtil.createKeyStore( "TIME_keys.jks", "password" );

                RSAPublicKey key = (RSAPublicKey ) SSLUtil.getPublicKey();
                System.out.println( Arrays.toString( key.getPublicExponent().toByteArray() ) );
                System.out.println( Arrays.toString( key.getModulus().toByteArray() ) );

                System.out.println( key.getModulus().toByteArray().length );

                //RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey( "time", "password".toCharArray() );

                //Signature signature = Signature.getInstance( "SHA1withRSA" );
                //signature.initSign( privateKey );
                //signature.update( new byte[]{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04} );
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
            catch ( ClassNotFoundException e )
            {
                e.printStackTrace();
            }
            catch ( KeyManagementException e )
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
        Parent root = FXMLLoader.load(getClass().getResource("/scene.fxml"));
        stage.setTitle("Middleware");
        stage.setScene(new Scene(root));
        stage.show();
    }
}
