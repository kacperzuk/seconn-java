seconn-java
===========

seconn-java is part of SeConn project. It's a protocol and set of libraries for secure communication. This repository contains Java library that implements the SeConn protocol. See also other repositories:

* [seconn](https://github.com/kacperzuk/seconn) - description of design and protocol, you should read it.
* [seconn-avr](https://github.com/kacperzuk/seconn-avr) - AVR library that implements the SeConn protocol
* [seconn-android-example](https://github.com/kacperzuk/seconn-android-example) - Example Android project that uses seconn-java
* [seconn-arduino-example](https://github.com/kacperzuk/seconn-arduino-example) - Example Arduino sketch that uses seconn-avr

Adding to your project
----------------------

In your app's build.gradle add:

```
repositories {
    maven {
        url 'https://dl.bintray.com/kacperzuk/Maven'
    }
}

...

dependencies {
    compile 'pl.kacperzuk.libs:seconn:1.0'
}
```

Usage
-----

seconn-java is agnostic when it comes to the network layer, IO is abstracted away. So the first thing you have to do is to implement SeConnHandler interface:

```java
import pl.kacperzuk.libs.seconn.SeConnHandler;

public class HandleConnection implements SeConnHandler {

    void writeData(byte[] data) {
        /*
         * This method is called when SeConn needs to write data to network.
         * For example we could pass this data to output stream of java.net.Socket
         */
        outputStream.write(data);
    }

    void onDataReceived(byte[] data) {
        /*
         * This method is called when SeConn received data from the other side
         * of connection. This data was encrypted in the network and
         * authenticated using public key from SeConn.public_key.
         * In other words that's the data from EncryptedData frame of SeConn
         * protocol.
         *
         * IMPORTANT! It's up to you to make sure that the public_key is
         * trusted!  SeConn only makes sure that data was sent by owner of the
         * key, not that key is trusted!
         */

         // we assume here that only printable characters were sent, but that
         // could actually be anything
         System.out.println("New data received from SeConn:");
         System.out.println(new String(data));
    }

    void onStateChange(SeConn.State previous_state, SeConn.State current_state) {
        /*
         * This method is called when connection's state changes. Possible
         * values are:
         * - NEW - the starting state
         * - HELLO_REQUEST_SENT - we sent HelloRequest frame to the other end
         *   and are waiting for HelloResponse
         * - INVALID_HANDSHAKE - the other side didn't prove that they're
         *   owners of public key they sent us
         * - SYNC_ERROR - some violation of protocol happened and we can't recover
         * - AUTHENTICATED - the other side correctly proved they're owners of
         *   public key, we can now send and receive encrypted and
         *   authenticated messages.
         */

         System.out.print("SeConn state changed from ");
         System.out.print(previous_state);
         System.out.print(" to ");
         System.out.println(current_state);
    }
}
```

The SeConnHandler covers receiving decrypted data in your app and sending raw data from SeConn to network. To transfer raw data from network to SeConn and to transfer data you want encrypted from your app to SeConn you'll have to use SeConn object:

```java
import pl.kacperzuk.libs.seconn.SeConn;

// somewhere after creating your network connection
HandleConnection handler = new HandleConnection();
SeConn seConn = new SeConn(handler);

// send HelloRequest when you now that the other side is listening
seConn.connect()

// after the state is AUTHENTICATED
// passing data that should be encrypted and sent to other side:
seConn.writeData("Hello from the other side!".getBytes());

// passing data from network to SeConn
InputStream in = ...;
byte[] buffer[10];
while(true) {
    int bytes = in.read(buffer);
    seConn.newData(Arrays.copyOfRange(bytes, 0, bytes));
}
```
