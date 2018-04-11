package be.msec;

import be.msec.smartcard.HelloWorldApplet;
import be.msec.smartcard.IdentityCard;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

/**
 * @author Pieter
 * @version 1.0
 */
public class Main
{
    public static void main( String[] args )
    {
        // 1. create simulator
        Simulator simulator = new Simulator();

        // 2. install applet
        AID appletAID = AIDUtil.create( "F000000001" );
        simulator.installApplet( appletAID, HelloWorldApplet.class );

        // 3. select applet
        simulator.selectApplet( appletAID );

        // 4. send APDU
        CommandAPDU  commandAPDU = new CommandAPDU( 0x00, 0x01, 0x00, 0x00 );
        ResponseAPDU response    = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        System.out.println(response);

        // 5. check response
        assertEquals( 0x9000, response.getSW() );
    }
}
