package be.msec.SP;

import be.msec.SSLUtil;
import com.rabbitmq.client.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.TimeoutException;

/**
 * @author Pieter
 * @version 1.0
 *
 * Start the docker container with: docker run -p 1883:1883 -p 15671:15671 -p 15672:15672 -p 15674:15674 -p 5672:5672 -p 8883:8883 -p 61613:61613 rmq
 */
public class ServiceProvider
{
    private static final Logger LOGGER = LoggerFactory.getLogger( ServiceProvider.class );

    private Connection connection;
    private Channel    channel;

    private ObjectInputStream  is;
    private ObjectOutputStream os;

    private boolean headlessMode = true;

    private SSLSocket c;

    private byte[] symmetricKey;

    public static void main( String[] args )
    {
        ServiceProvider serviceProvider = new ServiceProvider();

        try
        {
            serviceProvider.initAMQP();
        }
        catch ( IOException | TimeoutException e )
        {
            LOGGER.info( "starting headless" );
            serviceProvider.setHeadlessMode( true );
        }
        finally
        {
            serviceProvider.startSSLServer();
            serviceProvider.close();

        }
    }

    private void initAMQP() throws IOException, TimeoutException
    {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost( "localhost" );
        factory.setPort( 5672 );

        LOGGER.info( "Created factory" );

        connection = factory.newConnection();
        LOGGER.info( "Connected" );
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
                if ( c != null && c.isConnected() )
                {
                    log( "Received '" + message + "', sending certificate" );
                    //step 1
                    sendCertificate( message );

                    //step 2
                    respondChallenge( message );

                    //step 3
                    sendChallenge( message );

                    //step 4
                    requestPersonalInformation();
                }
                else
                {
                    log( "Received " + message + ", but no socket connection. Message will be ignored." );
                }
                channel.basicAck( envelope.getDeliveryTag(), true );

            }
        };

        channel.basicConsume( "sp", consumer );
        LOGGER.info( "created consumer for channel sp." );
    }

    private void sendChallenge( String message )
    {
        try
        {
            log( "Step 3: generating own challenge" );
            byte[] challenge = new byte[16]; // TODO: IF TESTED, USE SECURE RANDOM

            for (int i = 0; i < challenge.length; i++)
                challenge[i] = (byte) i;

            //generate hash for validation
            MessageDigest dig = MessageDigest.getInstance( "SHA-256" );
            dig.update( challenge );
            dig.update( new byte[]{ 0x41, 0x55, 0x54, 0x48} );
            byte[] digest = dig.digest();

            //encrypt that shit
            SecretKey key = new SecretKeySpec( symmetricKey, 0, 16, "AES" );

            Cipher          encryptCypher = Cipher.getInstance( "AES/CBC/NoPadding" );
            byte[]          ivdata        = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec spec          = new IvParameterSpec( ivdata );
            encryptCypher.init( Cipher.ENCRYPT_MODE, key, spec );

            byte encryptedChallenge[] = encryptCypher.doFinal( challenge, 0, 16 );

            log( "Encrypted challenge, now sending to middleware" );

            os.writeObject( new ByteArray( encryptedChallenge ) );

            log( "Sent challenge, awaiting response" );

            byte[] response = ((ByteArray) is.readObject()).getChallenge();

            log( "Received hash. Now decrypting" );
            encryptCypher.init( Cipher.DECRYPT_MODE, key, spec );
            short size = getEncodedSize( response );
            byte decryptedResponse[] = encryptCypher.doFinal( response, 2, size );

            SSLUtil.createKeyStore( "CA.jks", "password" );

            RSAPublicKey publicKey = (RSAPublicKey ) SSLUtil.getPublicKey( "CA" );
            Signature signature = Signature.getInstance( "SHA1withRSA" );
            signature.initVerify( publicKey );

            signature.update(  decryptedResponse, 0, 545 - 256 );
            boolean isValidCertificate = signature.verify( decryptedResponse, 545 - 256, 256 );

            BigInteger exp = new BigInteger( new byte[]{1,0,1} );
            byte[] mod = Arrays.copyOfRange( decryptedResponse, (545 - 256 - 256), 545 - 256 );
            BigInteger modulus = new BigInteger( 1, mod );
            RSAPublicKeySpec smartCardKey = new RSAPublicKeySpec( modulus, exp );
            publicKey = (RSAPublicKey) KeyFactory.getInstance( "RSA" ).generatePublic( smartCardKey );
            signature = Signature.getInstance( "SHA1withRSA" );
            signature.initVerify( publicKey );

            signature.update( digest );
            boolean isValidChallenge = signature.verify( decryptedResponse, 560, 256 );

            log( "Is valid common certificate: " + isValidCertificate );
            log( "Is valid decrypted and signed hash: " + isValidChallenge );
        }
        catch ( Exception e )
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

                LOGGER.info( "Opened ssl stream" );

                if ( headlessMode )
                {
                    String message = "DEFAULT1";
                    LOGGER.info( "No broker, using {} as service provider.", message );

                    //step 1
                    sendCertificate( message );

                    //step 2
                    respondChallenge( message );

                    //step 3
                    sendChallenge( message );

                    //step 4
                    requestPersonalInformation();
                }
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

            FileInputStream fis         = new FileInputStream( "cert_" + identifier + ".bob" );
            int             currentByte = 0;
            int             idx         = 0;
            byte[]          tmp         = new byte[1000];

            while ( (currentByte = fis.read()) != -1 )
                tmp[idx++] = (byte) currentByte;

            byte[] buffer = new byte[idx + 2];

            int certSize = idx - 256;

            buffer[0] = (byte) (certSize & 0xFF);
            buffer[1] = (byte) ((certSize >> 8) & 0xFF);

            for (int i = 0; i < idx; i++)
                buffer[i + 2] = tmp[i];

            System.out.println( Arrays.asList( buffer ) );

            os.writeObject( new ByteArray( buffer ) );
            log( "Sending certificate " + identifier + " to Middleware" );
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

    private void respondChallenge( String identifier )
    {
        try
        {
            log( "Waiting for symmetric key and challenge" );
            byte[] responseBuffer = ((ByteArray) is.readObject()).getChallenge();
            log( "Received symmetric key and challenge (encrypted)" );

            SSLUtil.createKeyStore( identifier + "_keys.jks", "password" );

            Cipher        rsaCipher  = Cipher.getInstance( "RSA/ECB/PKCS1PADDING" );
            RSAPrivateKey privateKey = (RSAPrivateKey) SSLUtil.getPrivateKey( identifier );

            rsaCipher.init( Cipher.DECRYPT_MODE, privateKey );

            byte[] symmKey = rsaCipher.doFinal( responseBuffer, 0, 256 );

            symmetricKey = symmKey;

            log( "Decrypted symmetric key" );

            SecretKey       key    = new SecretKeySpec( symmKey, 0, 16, "AES" );
            byte[]          ivdata = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec spec   = new IvParameterSpec( ivdata );
            Cipher          cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
            cipher.init( Cipher.DECRYPT_MODE, key, spec );

            byte result[] = cipher.doFinal( responseBuffer, 256, 32 );

            for (int i = 0; i < result.length; i++)
                result[i] += (byte) 1;

            log( "Decrypted challenge and increased each byte with 1" );

            Cipher encryptCypher = Cipher.getInstance( "AES/CBC/NoPadding" );
            encryptCypher.init( Cipher.ENCRYPT_MODE, key, spec );
            byte newChallenge[] = encryptCypher.doFinal( result, 0, 16 );

            log( "Wrote challenge" );
            os.writeObject( new ByteArray( newChallenge ) );
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

    private short getEncodedSize( byte[] buffer )
    {
        return (short) ((short) ((buffer[1] & 0xff) << 8) | ((short) buffer[0] & 0xff));
    }

    private void requestPersonalInformation()
    {
        for (int i = 0; i < 8; i++)
        {
            //ByteArray mask = (ByteArray) serviceProvider.receiveObject();

            byte[] mask = new byte[]{ (byte) (1 << i) };

            try
            {
                os.writeObject( new ByteArray( mask ) );


                SecretKey       key    = new SecretKeySpec( symmetricKey, 0, 16, "AES" );
                byte[]          ivdata = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                IvParameterSpec spec   = new IvParameterSpec( ivdata );
                Cipher          cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
                cipher.init( Cipher.DECRYPT_MODE, key, spec );

                byte[] responseBuffer = ((ByteArray) is.readObject()).getChallenge();
                if ( responseBuffer.length > 0 )
                {
                    byte result[] = cipher.doFinal( responseBuffer, 2, responseBuffer.length - 2 );

                    log( "received info for " + i );

                    if ( channel != null )
                        channel.basicPublish( "amq.topic", "data", null,
                                new IdentityInformation( Arrays.copyOfRange( result, 0, getEncodedSize( responseBuffer ) ), mask[0] ).generateJsonRepresentation() );

                }
                else
                {
                    log( "invalid request for data " + i );

                    if ( channel != null )
                        channel.basicPublish( "amq.topic", "data", null,
                                new IdentityInformation( mask[0] ).generateJsonRepresentation() );

                }

            }
            catch ( IOException e )
            {
                e.printStackTrace();
            }
            catch ( NoSuchAlgorithmException e )
            {
                e.printStackTrace();
            }
            catch ( InvalidKeyException e )
            {
                e.printStackTrace();
            }
            catch ( InvalidAlgorithmParameterException e )
            {
                e.printStackTrace();
            }
            catch ( NoSuchPaddingException e )
            {
                e.printStackTrace();
            }
            catch ( BadPaddingException e )
            {
                e.printStackTrace();
            }
            catch ( ClassNotFoundException e )
            {
                e.printStackTrace();
            }
            catch ( IllegalBlockSizeException e )
            {
                e.printStackTrace();
            }

        }

        log( "End session, clearing symmetric key and closing connection" );
        symmetricKey = null;
        close();
    }

    private void log( String event )
    {
        LOGGER.info( event );
        try
        {
            if ( channel != null )
                channel.basicPublish( "amq.topic", "card", null,
                        new Event( Event.Level.SUCCESS, event ).generateJsonRepresentation() );
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }

    }


    private void close()
    {
        try
        {
            if ( channel != null )
                channel.close();

            if ( connection != null )
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

    public boolean isHeadlessMode()
    {
        return headlessMode;
    }

    public void setHeadlessMode( boolean headlessMode )
    {
        this.headlessMode = headlessMode;
    }
}
