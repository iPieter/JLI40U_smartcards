package be.msec.SP;

import com.rabbitmq.client.BuiltinExchangeType;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * @author Pieter
 * @version 1.0
 */
public class ServiceProvider
{
    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceProvider.class);

    public static void main( String[] args )
    {

        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setPort( 5672 );
        Connection connection = null;
        try
        {
            connection = factory.newConnection();
            Channel    channel    = connection.createChannel();

            channel.exchangeDeclare("amq.topic", BuiltinExchangeType.TOPIC, true);


            for(int i = 0; i < 1000;i++)
            {


                channel.basicPublish("amq.topic", "card", null, new Card("key " + i).generateJsonRepresentation());
                System.out.println("send message " + i );
                Thread.sleep( 100 );

            }

            channel.close();
            connection.close();
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }
        catch ( TimeoutException e )
        {
            e.printStackTrace();
        }
        catch ( InterruptedException e )
        {
            e.printStackTrace();
        }

    }
}
