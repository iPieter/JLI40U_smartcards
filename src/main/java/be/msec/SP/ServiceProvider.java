package be.msec.SP;

import be.msec.SSLUtil;
import com.rabbitmq.client.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
            //start ssl server with root keys, because
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
//start ssl server with root keys, because
        try
        {
            SSLUtil.createKeyStore( identifier + "_keys.jks", "password" );
            Certificate certificate = SSLUtil.getCertificate( identifier.toLowerCase() );

            os.writeObject( certificate );
            System.out.println("sending " + certificate.toString());
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
