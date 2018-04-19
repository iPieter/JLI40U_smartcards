package be.msec.SP;

import org.nd4j.shade.jackson.core.JsonProcessingException;
import org.nd4j.shade.jackson.databind.ObjectMapper;
import org.nd4j.shade.jackson.databind.ObjectWriter;

import java.util.Arrays;
import java.util.Base64;

/**
 * @author Pieter
 * @version 1.0
 */
public class IdentityInformation
{
    private byte[]  data;
    private String  information;
    private boolean permission;

    public IdentityInformation( byte[] data, byte information )
    {
        this.data = data;
        this.permission = true;
        infoparser( information );
    }

    public String infoparser( byte info )
    {
        switch (info)
        {
            case 1 << 0:
                this.information = "Picture";
                if ( this.data != null )
                    this.data = Base64.getEncoder().encode( this.data );
                break;
            case 1 << 1:
                this.information = "Gender";
                break;
            case 1 << 2:
                this.information = "Age";
                break;
            case 1 << 3:
                this.information = "Birthday";
                break;
            case 1 << 4:
                this.information = "Country";
                break;
            case 1 << 5:
                this.information = "Address";
                if ( this.data != null )
                    this.data = removePadding( this.data );
                break;
            case 1 << 6:
                this.information = "Name";
                if ( this.data != null )
                    this.data = removePadding( this.data );
                break;
            case (byte) (1 << 7):
                if ( this.data != null )
                    this.data = Base64.getEncoder().encode( this.data );
                this.information = "Identifier";
                break;
            default:

        }

        return this.information;
    }

    public IdentityInformation( byte information )
    {
        this.permission = false;
        infoparser( information );
    }

    private byte[] removePadding( byte[] input )
    {
        int index = 0;
        while ( input[index++] == (byte) 48 )
        {
        }

        return Arrays.copyOfRange( input, index - 1, input.length );
    }


    public byte[] generateJsonRepresentation() throws JsonProcessingException
    {
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectWriter writer       = objectMapper.writerFor( this.getClass() );
        return writer.writeValueAsBytes( this );

    }

    public String getData()
    {
        if (data == null)
            return "";
        if ( information.equals( "Picture" ) )
            return "data:image/jpeg;base64," + new String( data );
        return new String( data );
    }


    public String getInformation()
    {
        return information;
    }

    public boolean isPermission()
    {
        return permission;
    }
}
