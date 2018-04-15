package be.msec.timestamp;

import be.msec.SSLUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.TreeSet;

/**
 * @author Pieter
 * @version 1.0
 */
public class Main
{
    private static final Logger LOGGER = LoggerFactory.getLogger( Main.class );

    public static void main( String[] args )
    {
        try
        {
            //init ssl
            SSLUtil.createKeyStore( "TIME_keys.jks", "password" );
            SSLContext context = SSLUtil.createServerSSLContext();

            LOGGER.info( "Opened keystore" );

            //init signing
            Signature signature = Signature.getInstance( "SHA1withRSA" );
            signature.initSign( (PrivateKey) SSLUtil.getPrivateKey("TIME") );

            LOGGER.info( "Created signer" );

            SSLServerSocketFactory ssf = context.getServerSocketFactory();
            SSLServerSocket        s   = (SSLServerSocket) ssf.createServerSocket( 1207 );
            //Arrays.stream( s.getEnabledCipherSuites() ).forEach( System.out::println );

            LOGGER.info( "Listening for connection" );

            while ( true )
            {
                SSLSocket c = (SSLSocket) s.accept();

                LOGGER.info( "Connection: " + Arrays.toString( c.getEnabledProtocols() ) );

                //DataInputStream is = new DataInputStream( c.getInputStream() );
                ObjectOutputStream os = new ObjectOutputStream( c.getOutputStream() );

                LOGGER.info( "Outputstream open" );

                Date             date   = new Date();
                Calendar calendar = Calendar.getInstance();
                calendar.setTime( date );
                calendar.add( Calendar.DATE, 1 );  // number of days to add

                SignedTimestamp signedTimestamp = new SignedTimestamp( date.getTime(), calendar.getTime().getTime(), signature );

                LOGGER.info( "Timestamp generated: " + signedTimestamp );

                os.writeObject( signedTimestamp );
                os.flush();

                LOGGER.info( "Object written" );

                os.close();
                c.close();

                LOGGER.info( "Closed connection" );
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
