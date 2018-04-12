package be.msec;

import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
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


            console = new DataInputStream( System.in );
            streamOut = new DataOutputStream( socket.getOutputStream() );

            while ( true )
            {
                String input  = "TEST";
                String ketqua = input.toUpperCase();
                streamOut.writeUTF( ketqua );
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
