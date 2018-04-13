package be.msec;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
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
        boolean PRINT_SHITTY_KEY = false;

        if( PRINT_SHITTY_KEY )
        {
            try
            {
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
