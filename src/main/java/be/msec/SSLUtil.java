package be.msec;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class SSLUtil
{
    private static String KEY_STORE_TYPE     = "JKS";
    private static String TRUST_STORE_TYPE   = "JKS";
    private static String KEY_MANAGER_TYPE   = "SunX509";
    private static String TRUST_MANAGER_TYPE = "SunX509";
    private static String PROTOCOL           = "TLS";

    private static KeyStore keyStore = null;
    private static String keyStorePassword;

    private static SSLContext serverSSLCtx = null;
    private static SSLContext clientSSLCtx = null;

    /**
     * Client or server agnostic method to create a key store based on a jks file.
     *
     * @param keyStoreLocation Path to the key store.
     * @param keyStorePassword Password to open the key store.
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public static void createKeyStore( final String keyStoreLocation, final String keyStorePassword )
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException
    {
        SSLUtil.keyStorePassword = keyStorePassword;
        keyStore = KeyStore.getInstance( KEY_STORE_TYPE );
        keyStore.load( new FileInputStream( keyStoreLocation ), keyStorePassword.toCharArray() );
    }

    /**
     * Create or obtain an ssl context for the server, based on the keystore from {@link #createKeyStore(String, String)}.
     *
     * @return The created ssl context
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws KeyManagementException
     */
    public static SSLContext createServerSSLContext()
            throws KeyStoreException,
            NoSuchAlgorithmException,
            CertificateException,
            IOException,
            UnrecoverableKeyException,
            KeyManagementException
    {
        assert keyStore != null; //initialize key store first

        if ( serverSSLCtx == null )
        {

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance( KEY_MANAGER_TYPE );
            keyManagerFactory.init( keyStore, keyStorePassword.toCharArray() );
            serverSSLCtx = SSLContext.getInstance( PROTOCOL );
            serverSSLCtx.init( keyManagerFactory.getKeyManagers(), null, null );
        }

        return serverSSLCtx;
    }


    public static SSLContext createClientSSLContext( final String trustStoreLocation, final String trustStorePwd )
            throws KeyStoreException,
            NoSuchAlgorithmException,
            CertificateException,
            IOException,
            KeyManagementException
    {
        if ( clientSSLCtx == null )
        {
            KeyStore trustStore = KeyStore.getInstance( TRUST_STORE_TYPE );
            trustStore.load( new FileInputStream( trustStoreLocation ), trustStorePwd.toCharArray() );
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance( TRUST_MANAGER_TYPE );
            trustManagerFactory.init( trustStore );
            clientSSLCtx = SSLContext.getInstance( PROTOCOL );
            clientSSLCtx.init( null, trustManagerFactory.getTrustManagers(), null );
        }

        return clientSSLCtx;

    }

    public static Key getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException
    {
        assert keyStore != null;

        Key key = keyStore.getKey( "time", "password".toCharArray() );

        return key;
    }

}
