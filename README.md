# Veilige software: smartcard project


## Running the project
_By default with the simulator_

### Generating keys
There are keys included in this project by default but if you want to generate your own keys, you can execute `GeneratorMain.java`.

Make sure to copy the keys into `IdentityCard.java`, because those have to be hardcoded.

```
$java -cp smartcard.jar be.msec.certificates.GeneratorMain
```

### Time server `G`
Launch `timestamp/Main.java` It will start a SSL Socket server with the key store `TIME_keys.jks`.

After launch, it will sequentially accept new connections until terminated.

```
$java -cp smartcard.jar be.msec.timestamp.Main
```

### Service provider `SP`
The service provider has two operation modes:

- *Remote mode:* This uses an AMQP-connection to stream all events to a dashboard.
- *Headless Mode:* This simply prints out all received information, however identity info is unreadable. Also,  there is no option to select another service provider.

Headless mode is used by default, if there is no connection to an AMQP-server available. Simply run `ServiceProvider.java`.

To start in remote mode, an AMQP-server needs to be present on port `5672` (default). To quickly start, the following dockerfile creates a rabbitMQ image with all the necessary components.

_it is also available as file in `src/main/js`_

```
FROM rabbitmq

RUN rabbitmq-plugins enable --offline rabbitmq_management
RUN rabbitmq-plugins enable --offline rabbitmq_stomp
RUN rabbitmq-plugins enable --offline rabbitmq_web_stomp
RUN rabbitmq-plugins enable --offline rabbitmq_amqp1_0

EXPOSE 15671 15672 15674 61613
EXPOSE 1883
EXPOSE 8883
EXPOSE 5672
```

finally run it with:

```
docker run -p 1883:1883 -p 15671:15671 -p 15672:15672 -p 15674:15674 -p 5672:5672 -p 8883:8883 -p 61613:61613 rmq
```

After this, you can start `ServiceProvider.java` and open `index.html` as a regular file in your favorite browser. _Not like some other smart card services which require some version of some ancient browser._

Or from a jar:

```
$java -cp smartcard.jar be.msec.SP.ServiceProvider
```

### Running the Middleware
Finally you can launch the middleware by calling `be.msec.Main.java`.

Or from a jar:

```
$java -cp smartcard.jar be.msec.Main
```

## Building applets

 * Download [`ant-javacard.jar`](https://github.com/martinpaljak/ant-javacard/releases/download/18.01.17/ant-javacard.jar) (be sure to get the [latest version](https://github.com/martinpaljak/ant-javacard/releases/latest))
   * The **only** supported Java version for all SDK targets is 1.8!
 * Check the path in your `build.xml` file:
```xml
<taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="ant-javacard.jar"/>
```
 * Now you can create applets within your Ant targets like this:
```xml
<javacard>
  <cap jckit="/path/to/jckit_dir" aid="0102030405" output="MyApplet.cap" sources="src/myapplet">
    <applet class="myapplet.MyApplet" aid="0102030405060708"/>
  </cap>
</javacard>
```
(which results in output similar to this)
```
target:
      [cap] INFO: using JavaCard v2.2.2 SDK in ../jc222_kit
      [cap] Setting package name to testapplets
      [cap] Building CAP with 1 applet from package testapplets
      [cap] testapplets.Empty 0102030405060708
  [compile] Compiling 1 source file to /var/folders/l7/h99c5w6j0y1b8_qbsth_9v4r0000gn/T/antjc4506897175807383834
      [cap] CAP saved to /Users/martin/projects/ant-javacard/Empty222.cap
```
## The giants we stood on
 * Cross-platform Javacard Ant task [javacard.pro](https://javacard.pro)