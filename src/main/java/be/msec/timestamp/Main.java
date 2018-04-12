package be.msec.timestamp;

import be.msec.SSLUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.TreeSet;

/**
 * @author Pieter
 * @version 1.0
 */
public class Main
{
    public static void main( String[] args )
    {
        try
        {
            //init ssl
            SSLUtil.createKeyStore( "TIME_keys.jks", "password" );
            SSLContext context = SSLUtil.createServerSSLContext();

            TreeSet <String> algorithms = new TreeSet <>();
            for (Provider provider : Security.getProviders())
                for (Provider.Service service : provider.getServices())
                    if ( service.getType().equals( "Signature" ) )
                        algorithms.add( service.getAlgorithm() );
            for (String algorithm : algorithms)
                System.out.println( algorithm );

            //init signing
            Signature signature = Signature.getInstance( "SHA1withRSA" );
            signature.initSign( (PrivateKey) SSLUtil.getPrivateKey() );

            SSLServerSocketFactory ssf = context.getServerSocketFactory();
            SSLServerSocket        s   = (SSLServerSocket) ssf.createServerSocket( 1207 );
            Arrays.stream( s.getEnabledCipherSuites() ).forEach( System.out::println );

            SSLSocket c = (SSLSocket) s.accept();


            DataInputStream is = new DataInputStream( c.getInputStream() );
            PrintStream     os = new PrintStream( c.getOutputStream() );
            while ( true )
            {
                signature.update( "123456".getBytes() );

                byte[] sig = signature.sign();

                System.out.println("SIGNED ('123456'): " + sigLength);

                String input  = is.readUTF();
                String ketqua = input.toUpperCase();
                os.println( ketqua );
            }
        }
        catch ( IOException e )
        {
            System.out.print( e );
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
        catch ( KeyStoreException e )
        {
            e.printStackTrace();
        }
        catch ( KeyManagementException e )
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
}
