package be.msec.certificates;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * @author Pieter
 * @version 1.0
 */
public class GeneratorMain
{
    public static String[] PROVIDERS = { "GOV1", "GOV2", "SOCNET1", "SOCNET2", "DEFAULT1", "DEFAULT2", "CUSTOM1", "CUSTOM2", "TIME" };

    public static void main( String[] args )
    {
        try
        {
            //Generate root certificate
            CertAndKeyGen keyGen = new CertAndKeyGen( "RSA", "SHA1WithRSA", null );
            keyGen.generate( 2048 );
            PrivateKey rootPrivateKey = keyGen.getPrivateKey();

            X509Certificate rootCertificate = keyGen.getSelfCertificate( new X500Name( "CN=ROOT" ), (long) 365 * 24 * 60 * 60 );

            storeKeyAndCertificateChain( "CA", "password".toCharArray(), "CA.jks", rootPrivateKey, new X509Certificate[]{ rootCertificate } );

            Arrays.stream( PROVIDERS ).forEach( name -> generateLeafProvider( name, rootCertificate, rootPrivateKey ) );
        }
        catch ( Exception ex )
        {
            ex.printStackTrace();
        }
    }

    private static void storeKeyAndCertificateChain( String alias, char[] password, String keystore, Key key, X509Certificate[] chain ) throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance( "jks" );
        keyStore.load( null, null );

        File storeFile = new File( keystore );

        FileOutputStream outputStream = new FileOutputStream( storeFile );

        keyStore.setKeyEntry( alias, key, password, chain );
        keyStore.store( outputStream, password );


    }

    public static void generateLeafProvider( String provider, X509Certificate rootCertificate, PrivateKey rootPrivateKey )
    {
        //Generate leaf certificate
        CertAndKeyGen keyGen2 = null;
        try
        {
            keyGen2 = new CertAndKeyGen( "RSA", "SHA1WithRSA", null );

            keyGen2.generate( 2048 );
            PrivateKey topPrivateKey = keyGen2.getPrivateKey();

            X509Certificate topCertificate = keyGen2.getSelfCertificate( new X500Name( "CN=" + provider ), (long) 31 * 24 * 60 * 60 );

            //rootCertificate = createSignedCertificate( "ROOT", rootCertificate, rootCertificate, rootPrivateKey );
            topCertificate = createSignedCertificate( "CN=" + provider, topCertificate, rootCertificate, rootPrivateKey );
            //topCertificate = createSignedCertificate( "CN=" + provider, topCertificate, rootCertificate, rootPrivateKey );

            X509Certificate[] chain = new X509Certificate[2];
            chain[0] = topCertificate;
            chain[1] = rootCertificate;

            char[] password = "password".toCharArray();
            String keystore = provider + "_keys.jks";

            //Store the certificate chain
            storeKeyAndCertificateChain( provider, password, keystore, topPrivateKey, chain );

            //Reload the keystore and display key and certificate chain info
            //loadAndDisplayChain( provider, password, keystore );

            //Clear the keystore
            //clearKeyStore( provider, password, keystore );

        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }
    }

    private static void loadAndDisplayChain( String alias, char[] password, String keystore ) throws Exception
    {
        //Reload the keystore
        KeyStore keyStore = KeyStore.getInstance( "jks" );
        keyStore.load( new FileInputStream( keystore ), password );

        Key key = keyStore.getKey( alias, password );

        if ( key instanceof PrivateKey )
        {
            System.out.println( "Get private key : " );
            System.out.println( key.toString() );

            Certificate[] certs = keyStore.getCertificateChain( alias );
            System.out.println( "Certificate chain length : " + certs.length );
            for (Certificate cert : certs)
            {
                System.out.println( cert.toString() );
            }
        }
        else
        {
            System.out.println( "Key is not private key" );
        }
    }

    private static void clearKeyStore( String alias, char[] password, String keystore ) throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance( "jks" );
        keyStore.load( new FileInputStream( keystore ), password );
        keyStore.deleteEntry( alias );
        keyStore.store( new FileOutputStream( keystore ), password );
    }

    private static X509Certificate createSignedCertificate( String name, X509Certificate certificate, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey )
    {
        try
        {
            Principal issuer       = issuerCertificate.getSubjectDN();
            String    issuerSigAlg = issuerCertificate.getSigAlgName();

            byte[]       inCertBytes = certificate.getTBSCertificate();
            X509CertInfo info        = new X509CertInfo( inCertBytes );
            info.set( X509CertInfo.ISSUER, issuer );

            //No need to add the BasicContraint for leaf cert
            //if ( !certificate.getSubjectDN().getName().equals( "CN=TOP" ) )
            //{
            //    CertificateExtensions     exts = new CertificateExtensions();
            //    BasicConstraintsExtension bce  = new BasicConstraintsExtension( true, -1 );
            //    exts.set( BasicConstraintsExtension.NAME, new BasicConstraintsExtension( false, bce.getExtensionValue() ) );
            //    info.set( X509CertInfo.EXTENSIONS, exts );
            //}

            X509CertImpl outCert = new X509CertImpl( info );
            outCert.sign( issuerPrivateKey, issuerSigAlg );

            return outCert;
        }
        catch ( Exception ex )
        {
            ex.printStackTrace();
        }
        return null;
    }
}
