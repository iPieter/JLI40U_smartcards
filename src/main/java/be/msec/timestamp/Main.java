package be.msec.timestamp;

import be.msec.SSLUtil;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

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
            SSLContext context = SSLUtil.createServerSSLContext( "TIME_keys.jks", "password" );

            SSLServerSocketFactory ssf = context.getServerSocketFactory();
            SSLServerSocket        s   = (SSLServerSocket) ssf.createServerSocket( 1207 );
            Arrays.stream( s.getEnabledCipherSuites() ).forEach( System.out::println );

            SSLSocket              c   = (SSLSocket) s.accept();


            DataInputStream is = new DataInputStream( c.getInputStream() );
            PrintStream     os = new PrintStream( c.getOutputStream() );
            while ( true )
            {
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
    }
}
