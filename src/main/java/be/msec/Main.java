package be.msec;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import sun.security.x509.X509CertImpl;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
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
        boolean PRINT_SHITTY_KEY = true;

        if( PRINT_SHITTY_KEY )
        {
            try
            {
                //TODO: this is for anton
                SSLUtil.createKeyStore( "TIME_keys.jks", "password" );

                System.out.println("---info---");
                byte[] info =  SSLUtil.getInfo("time");
                System.out.println( Arrays.toString( info ) );
                System.out.println("---signature---");
                byte[] sign =  SSLUtil.getCertificate("time").getSignature();
                System.out.println( Arrays.toString(  sign ) );

                //RSAPublicKey key = (RSAPublicKey ) SSLUtil.getPublicKey();
                //System.out.println( Arrays.toString( key.getPublicExponent().toByteArray() ) );
                //System.out.println( Arrays.toString( key.getModulus().toByteArray() ) );

                //System.out.println( key.getModulus().toByteArray().length );

                SSLUtil.createKeyStore( "CA.jks", "password" );

                PublicKey publicKey = SSLUtil.getPublicKey();

                Signature signature = Signature.getInstance( "SHA1withRSA" );
                signature.initVerify( publicKey );
                signature.update( info );
                System.out.println(signature.verify( sign ));
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


    @Override
    public void start( Stage stage ) throws Exception
    {
        Parent root = FXMLLoader.load(getClass().getResource("/scene.fxml"));
        stage.setTitle("Middleware");
        stage.setScene(new Scene(root));
        stage.show();
    }
}
