package be.msec.SP;

import com.rabbitmq.tools.json.JSONSerializable;
import com.rabbitmq.tools.json.JSONWriter;
import org.nd4j.shade.jackson.core.JsonProcessingException;
import org.nd4j.shade.jackson.databind.ObjectMapper;
import org.nd4j.shade.jackson.databind.ObjectWriter;

/**
 * @author Pieter
 * @version 1.0
 */
public class Card
{
    private String key;

    public Card( String key )
    {
        this.key = key;
    }


    public byte[] generateJsonRepresentation() throws JsonProcessingException
    {
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectWriter writer       = objectMapper.writerFor( this.getClass() );
        return writer.writeValueAsBytes( this );

    }

    public String getKey()
    {
        return key;
    }

    public void setKey( String key )
    {
        this.key = key;
    }
}
