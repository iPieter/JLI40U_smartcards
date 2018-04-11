package be.msec;

import be.msec.smartcard.IdentityCard;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class Controller
{
    @FXML
    private Button pinButton;

    @FXML
    private TextArea logPanel;

    @FXML
    private PasswordField pinField;

    public Controller()
    {
        Simulator simulator = new Simulator();

        AID appletAID = AIDUtil.create( "F000000001" );
        simulator.installApplet( appletAID, IdentityCard.class );

        simulator.selectApplet( appletAID );

        CommandAPDU  commandAPDU;
        ResponseAPDU response;

        commandAPDU = new CommandAPDU( 0x80, 0x22, 0x00, 0x00, new byte[]{ 0x01, 0x02, 0x03, 0x04 } );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        System.out.println( response );

        commandAPDU = new CommandAPDU( 0x80, 0x24, 0x00, 0x00 );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        System.out.println( response );

        System.out.println( new BigInteger( 1, response.getData() ).toString( 16 ) );

        long now = System.currentTimeMillis();
        byte [] time = ByteBuffer.allocate( Long.SIZE / Byte.SIZE ).putLong( now ).array();

        commandAPDU = new CommandAPDU( 0x80, 0x26, 0x00, 0x00, time );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        System.out.println( response );
        System.out.println( Arrays.toString( response.getData() ) );

        commandAPDU = new CommandAPDU( 0x80, 0x26, 0x00, 0x00, time );
        response = new ResponseAPDU( simulator.transmitCommand( commandAPDU.getBytes() ) );

        System.out.println( response );
        System.out.println( Arrays.toString( response.getData() ) );

    }

    @FXML
    public void initialize()
    {
        write( "Application loaded." );
    }


    private void write( String text )
    {
        logPanel.appendText( text + " \n" );
    }

    public void login()
    {
        logPanel.appendText( "Logging in \n" );
    }
}
