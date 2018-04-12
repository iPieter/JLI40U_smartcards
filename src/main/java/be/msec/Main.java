package be.msec;

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
    private static SSLSocket        socket    = null;
    private static Thread           thread    = null;
    private static DataInputStream  console   = null;
    private static DataOutputStream streamOut = null;

    private static final char[] passphrase = "password".toCharArray();

    public static void main( String[] args )
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
        catch ( KeyStoreException e )
        {
            e.printStackTrace();
        }
        catch ( KeyManagementException e )
        {
            e.printStackTrace();
        }
        catch ( ClassNotFoundException e )
        {
            e.printStackTrace();
        }
    }
}
