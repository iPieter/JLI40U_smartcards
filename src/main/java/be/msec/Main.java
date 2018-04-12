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

/**
 * @author Pieter
 * @version 1.0
 */
public class Main extends Application
{
    /**
     * Client or server agnostic method to create a key store based on a jks file.
     *
     * @param keyStoreLocation Path to the key store.
     * @param keyStorePassword Password to open the key store.
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public static KeyStore createKeyStore( final String keyStoreLocation, final String keyStorePassword )
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException
    {
        KeyStore keyStore = KeyStore.getInstance( "JKS" );
        keyStore.load( new FileInputStream( keyStoreLocation ), "password".toCharArray() );

        return keyStore;
    }

    public static void main( String[] args )
    {
        boolean PRINT_SHITTY_KEY = false;

        if( PRINT_SHITTY_KEY )
        {
            try
            {
                KeyStore keyStore = createKeyStore( "/home/anton/Desktop/ku leuven/vakken/semester 8/veilige software/JLI40U_smartcards/res/TIME_keys.jks", "" );

                RSAPublicKey key = (RSAPublicKey ) keyStore.getCertificate( "time" ).getPublicKey();
                System.out.println( Arrays.toString( key.getPublicExponent().toByteArray() ) );
                System.out.println( Arrays.toString( key.getModulus().toByteArray() ) );

                System.out.println( key.getModulus().toByteArray().length );

                RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey( "time", "password".toCharArray() );

                Signature signature = Signature.getInstance( "SHA1withRSA" );
                signature.initSign( privateKey );
                signature.update( new byte[]{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04} );

                System.out.println( Arrays.toString( signature.sign() ) );
                System.out.println( signature.sign().length );
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
            catch ( UnrecoverableKeyException e )
            {
                e.printStackTrace();
            }
            catch ( InvalidKeyException e )
            {
                e.printStackTrace();
            }
            catch ( SignatureException e )
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
