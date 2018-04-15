package be.msec.certificates;

import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.stream.IntStream;

/**
 * @author Pieter
 * @version 1.0
 */
public class GeneratorMain
{
    public static String[] PROVIDERS = { "GOV1", "GOV2", "SOCNET1", "SOCNET2", "DEFAULT1", "DEFAULT2", "CUSTOM1", "CUSTOM2", "TIME", "SMARTCARD" };
    public static String[] TYPES     = { "A", "A", "B", "B", "C", "C", "D", "D", "G", "Z" };

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

            IntStream.range( 0, PROVIDERS.length ).forEach( idx -> { generateLeafProvider( PROVIDERS[idx], TYPES[idx], rootCertificate, rootPrivateKey ); } );
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

    public static void generateLeafProvider( String provider, String type, X509Certificate rootCertificate, PrivateKey rootPrivateKey )
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

            String       name       = leftPad( provider, 16 );
            long         beforeDate = topCertificate.getNotBefore().getTime();
            long         afterDate  = topCertificate.getNotAfter().getTime();
            RSAPublicKey pk         = (RSAPublicKey) topCertificate.getPublicKey();


            byte [] nameBytes   = name.getBytes();
            byte [] beforeBytes = ByteBuffer.allocate( Long.SIZE / Byte.SIZE ).putLong( beforeDate ).array();
            byte [] afterBytes  = ByteBuffer.allocate( Long.SIZE / Byte.SIZE ).putLong( afterDate ).array();
            byte [] classBytes  = type.getBytes();
            byte [] pkModulus   = pk.getModulus().toByteArray();

            byte [] certificate = new byte[ nameBytes.length + beforeBytes.length + afterBytes.length + classBytes.length + pkModulus.length - 1 ];
            fill( certificate, nameBytes, classBytes, beforeBytes, afterBytes, pkModulus );

            Signature signer = Signature.getInstance( "SHA1withRSA" );
            signer.initSign( rootPrivateKey );
            signer.update( certificate );
            byte [] signature = signer.sign();

            FileOutputStream fos = new FileOutputStream( "cert_" + provider + ".bob" );
            fos.write( certificate );
            fos.write( signature );
            fos.flush();
            fos.close();

            System.out.println( "" );

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

    private static void fill( byte[] certificate, byte[] nameBytes, byte[] classBytes, byte[] beforeBytes, byte[] afterBytes, byte[] pkModulus )
    {
        int off = 0;
        for( int i = 0; i < nameBytes.length; i++ )
            certificate[i + off] = nameBytes[i];
        off += nameBytes.length;

        for( int i = 0; i < classBytes.length; i++ )
            certificate[i + off] = classBytes[i];
        off += classBytes.length;

        for( int i = 0; i < beforeBytes.length; i++ )
            certificate[i + off] = beforeBytes[i];
        off += beforeBytes.length;

        for( int i = 0; i < afterBytes.length; i++ )
            certificate[i + off] = afterBytes[i];
        off += afterBytes.length;

        for( int i = 1; i < pkModulus.length; i++ )
            certificate[i + off - 1] = pkModulus[i];
    }

    private static String leftPad( String original, int length )
    {
        int difference = length - original.length();
        if( difference < 0 )
            return original;

        String padding = "";
        for( int i = 0; i < difference; i++ )
            padding += "0";

        return padding + original;
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
