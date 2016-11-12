package pl.kacperzuk.libs.seconn;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.util.Arrays;

public class SeConn {
    public enum State {
        NEW,
        HELLO_REQUEST_SENT,
        INVALID_HANDSHAKE,
        SYNC_ERROR,
        AUTHENTICATED;
    }

    private final Crypto crypto;
    private final SeConnHandler handler;

    private State state;
    private byte[] buffer;

    public byte[] public_key;

    public SeConn(SeConnHandler _handler) {
        this(_handler, null);
    }

    public SeConn(SeConnHandler _handler, KeyPairBytes keyPairBytes) {
        crypto = new Crypto(keyPairBytes);
        handler = _handler;
        state = State.NEW;
        buffer = new byte[0];
    }

    public byte[] getOurPublicKey() {
        return crypto.getPubKey();
    }

    public void connect() {
        sendHelloRequest();
    }

    public KeyPairBytes getKeyPair() {
        return crypto.getKeyPair();
    }

    public void writeData(byte[] data) {
        byte[] encryptedData = crypto.encryptThenMac(data);
        byte[] message = Proto.CreateMessage(Message.MessageType.EncryptedData, encryptedData);
        handler.writeData(message);
    }

    private void sendHelloRequest() {
        byte[] message = Proto.CreateMessage(Message.MessageType.HelloRequest, crypto.getPubKey());
        changeState(State.HELLO_REQUEST_SENT);
        handler.writeData(message);
    }

    private void sendHelloResponse() {
        byte[] key = crypto.getPubKey();
        byte[] encrypted_key = crypto.encryptThenMac(key);
        byte[] message = Proto.CreateMessage(Message.MessageType.HelloResponse, encrypted_key);
        handler.writeData(message);
    }

    private void changeState(State new_state) {
        State prev_state = state;
        state = new_state;
        handler.onStateChange(prev_state, new_state);
    }

    public void newData(byte[] data) {
        if (state == State.INVALID_HANDSHAKE || state == State.SYNC_ERROR)
            return;

        byte[] new_buffer = new byte[data.length + buffer.length];
        System.arraycopy(buffer, 0, new_buffer, 0, buffer.length);
        System.arraycopy(data, 0, new_buffer, buffer.length, data.length);
        buffer = new_buffer;

        ParseResult result = Proto.ParseMessage(buffer);
        if (result.getResult() == ParseResult.Result.TOO_SHORT) {
            return;
        } else if (result.getResult() != ParseResult.Result.OK) {
            changeState(State.SYNC_ERROR);
            buffer = new byte[0];
            return;
        }

        buffer = Arrays.copyOfRange(buffer, result.getBytesConsumed(), buffer.length);

        Message msg = result.getMessage();

        if (msg.type == Message.MessageType.HelloRequest) {
            public_key = msg.raw_payload;
            byte[] secret;
            try {
                crypto.generateSecret(public_key);
            } catch (InvalidKeyException e) {
                e.printStackTrace();
                changeState(State.SYNC_ERROR);
                return;
            }

            if (state == State.NEW) {
                sendHelloRequest();
            }
            // violate the protocol. avr wont be able to receive helloresponse when handling hellorequest, we'll send it after hello response
        } else if (msg.type == Message.MessageType.HelloResponse) {
            if (!crypto.checkMac(msg.raw_payload)) {
                changeState(State.SYNC_ERROR);
                return;
            }
            byte[] decrypted = crypto.decrypt(msg.raw_payload);
            if (!MessageDigest.isEqual(decrypted, public_key)) {
                changeState(State.INVALID_HANDSHAKE);
                return;
            }
            changeState(State.AUTHENTICATED);
            sendHelloResponse();
        } else if (msg.type == Message.MessageType.EncryptedData) {
            if (!crypto.checkMac(msg.raw_payload)) {
                changeState(State.SYNC_ERROR);
                return;
            }
            byte[] decrypted = crypto.decrypt(msg.raw_payload);
            handler.onDataReceived(decrypted);
        } else {
            changeState(State.SYNC_ERROR);
        }

        if (buffer.length > 0) {
            newData(new byte[0]);
        }
    }


    public static String toHex(byte[] array) {
        String ret = "0x";
        String alphabet = "0123456789ABCDEF";
        for (byte b : array) {
            ret += alphabet.charAt((b & 0xF0) >> 4);
            ret += alphabet.charAt(b & 0x0F);
        }
        return ret;
    }

    public static String toUint8Array(byte[] array) {
        String ret = "{ ";
        for (int i = 0; i < array.length; i++) {
            ret += String.valueOf(0xFF & array[i]);
            if (i != array.length - 1) {
                ret += ", ";
            }
        }
        ret += "}";
        return ret;
    }
}
