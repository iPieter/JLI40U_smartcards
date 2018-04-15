package be.msec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

/**
 * Provides utility methods to write, read and construct a SSL tunnel to a SSL Socket server.
 * <p>
 * Doesn't provide background work,
 *
 * @author Pieter
 * @version 1.0
 */
public class SSLClient
{
    private static final Logger LOGGER = LoggerFactory.getLogger( SSLClient.class );

    private SSLSocket          socket;
    private ObjectInputStream  is;
    private ObjectOutputStream os;

    public SSLClient( String host, int port )
    {
        this( host, port, "CA.jks", "password" );
    }

    public SSLClient( String host, int port, String ca, String password )
    {
        try
        {
            SSLContext context = SSLUtil.createClientSSLContext( ca, password );
            socket = (SSLSocket) context.getSocketFactory().createSocket( host, port );

            this.os = new ObjectOutputStream( socket.getOutputStream() );
            this.is = new ObjectInputStream( socket.getInputStream() );

            LOGGER.info( "Established session with {} : {}", host, port );
        }
        catch ( KeyStoreException e )
        {
            e.printStackTrace();
        }
        catch ( NoSuchAlgorithmException e )
        {
            e.printStackTrace();
        }
        catch ( CertificateException e )
        {
            e.printStackTrace();
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        catch ( KeyManagementException e )
        {
            e.printStackTrace();
        }
    }

    public void writeObject( Object object )
    {
        assert object != null;
        assert socket.isConnected();
        assert os != null;

        try
        {
            os.writeObject( object );
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
    }

    public Object receiveObject()
    {
        assert socket.isConnected();
        assert is != null;

        try
        {
            return is.readObject();
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        catch ( ClassNotFoundException e )
        {
            e.printStackTrace();
        }
        return null;
    }

    public void close()
    {
        try
        {
            os.close();
            is.close();
            socket.close();

            LOGGER.info( "Closed SSL session to {} : {}. ", socket.getInetAddress().getHostName(), socket.getPort() );
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
    }
}
