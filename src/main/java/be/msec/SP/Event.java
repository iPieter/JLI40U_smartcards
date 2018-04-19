package be.msec.SP;

import org.nd4j.shade.jackson.core.JsonProcessingException;
import org.nd4j.shade.jackson.databind.ObjectMapper;
import org.nd4j.shade.jackson.databind.ObjectWriter;

import java.util.Date;

/**
 * @author Pieter
 * @version 1.0
 */
public class Event
{
    enum Level {
        SUCCESS,
        FAILURE,
        WARNING
    }

    private String event;
    private Level level;
    private Date date;

    public Event( Level level, String event )
    {
        this.event = event;
        this.level = level;
        this.date = new Date();
    }

    public byte[] generateJsonRepresentation() throws JsonProcessingException
    {
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectWriter writer       = objectMapper.writerFor( this.getClass() );
        return writer.writeValueAsBytes( this );

    }

    public String getEvent()
    {
        return event;
    }

    public void setEvent( String event )
    {
        this.event = event;
    }

    public Level getLevel()
    {
        return level;
    }

    public void setLevel( Level level )
    {
        this.level = level;
    }

    public Date getDate()
    {
        return date;
    }

    public void setDate( Date date )
    {
        this.date = date;
    }
}
