package be.msec.SP;

import be.msec.SSLUtil;
import com.rabbitmq.client.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.concurrent.TimeoutException;

/**
 * @author Pieter
 * @version 1.0
 */
public class ServiceProvider
{
    private static final Logger LOGGER = LoggerFactory.getLogger( ServiceProvider.class );

    private Connection connection;
    private Channel    channel;

    private ObjectInputStream  is;
    private ObjectOutputStream os;

    private SSLSocket c;

    public static void main( String[] args )
    {
        ServiceProvider serviceProvider = new ServiceProvider();


        serviceProvider.initAMQP();
        serviceProvider.startSSLServer();
        serviceProvider.close();
    }

    private void initAMQP()
    {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost( "localhost" );
        factory.setPort( 5672 );
        connection = null;
        try
        {
            connection = factory.newConnection();
            channel = connection.createChannel();

            channel.exchangeDeclare( "amq.topic", BuiltinExchangeType.TOPIC, true );

            Consumer consumer = new DefaultConsumer( channel )
            {
                @Override
                public void handleDelivery( String consumerTag, Envelope envelope,
                                            AMQP.BasicProperties properties, byte[] body )
                        throws IOException
                {
                    String message = new String( body, "UTF-8" );
                    System.out.println( " [x] Received '" + message + "', sending certificate" );
                    sendCertificate( message );
                    channel.basicAck( envelope.getDeliveryTag(), true );

                    sendChallenge( message );
                }
            };

            channel.basicConsume( "sp", consumer );
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        catch ( TimeoutException e )
        {
            e.printStackTrace();
        }
    }

    private void startSSLServer()
    {
        //init ssl
        try
        {
            //start ssl server with root keys, because type is chosen later
            SSLUtil.createKeyStore( "CA.jks", "password" );
            SSLContext context = SSLUtil.createServerSSLContext();

            //init signing
            Signature signature = Signature.getInstance( "SHA1withRSA" );
            signature.initSign( (PrivateKey) SSLUtil.getPrivateKey( "ca" ) );

            SSLServerSocketFactory ssf = context.getServerSocketFactory();
            SSLServerSocket        s   = (SSLServerSocket) ssf.createServerSocket( 1271 );
            //Arrays.stream( s.getEnabledCipherSuites() ).forEach( System.out::println );

            while ( true )
            {
                c = (SSLSocket) s.accept();


                is = new ObjectInputStream( c.getInputStream() );
                os = new ObjectOutputStream( c.getOutputStream() );

                System.out.println( "received card from ssl stream" );

                channel.basicPublish( "amq.topic", "card", null, ((Card) is.readObject()).generateJsonRepresentation() );

            }


        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

    private void sendCertificate( String identifier )
    {
        try
        {
            //TODO change for real cert
            SSLUtil.createKeyStore( identifier + "_keys.jks", "password" );
            Certificate certificate = SSLUtil.getCertificate( identifier );

            os.writeObject( certificate );
            System.out.println( "sending " + certificate.toString() );
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

    private void sendChallenge( String identifier )
    {
        try
        {
            byte[] responseBuffer = ((ByteArray) is.readObject()).getChallenge();

            SSLUtil.createKeyStore( identifier + "_keys.jks", "password" );

            Cipher        rsaCipher  = Cipher.getInstance( "RSA/ECB/PKCS1PADDING" );
            RSAPrivateKey privateKey = (RSAPrivateKey) SSLUtil.getPrivateKey( "GOV1" );

            rsaCipher.init( Cipher.DECRYPT_MODE, privateKey );

            byte[] symmKey = rsaCipher.doFinal( responseBuffer, 0, 256 );

            System.out.println( Arrays.toString( symmKey ) );

            SecretKey       key    = new SecretKeySpec( symmKey, 0, 16, "AES" );
            byte[]          ivdata = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec spec   = new IvParameterSpec( ivdata );
            Cipher          cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
            cipher.init( Cipher.DECRYPT_MODE, key, spec );

            byte result[] = cipher.doFinal( responseBuffer, 256, 32 );

            for (int i = 0; i < result.length; i++)
                result[i] += (byte) 1;

            Cipher encryptCypher = Cipher.getInstance( "AES/CBC/NoPadding" );
            encryptCypher.init( Cipher.ENCRYPT_MODE, key, spec );
            byte newChallenge[] = encryptCypher.doFinal( result, 0, 16 );

            os.writeObject( new ByteArray( newChallenge ) );
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }


    private void close()
    {
        try
        {
            channel.close();
            connection.close();
            is.close();
            os.close();
            c.close();

        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        catch ( TimeoutException e )
        {
            e.printStackTrace();
        }
    }
}
