package pl.kacperzuk.libs.seconn;

import java.util.Arrays;

/**
 * Created by kaz on 11.11.16.
 */

public class Proto {
    private static final byte[] PROTOCOL_VERSION = new byte[] { 0x00, 0x01 };

    public static byte[] CreateMessage(Message.MessageType type, byte[] data) {
        byte[] ret = new byte[5+data.length];
        System.arraycopy(PROTOCOL_VERSION, 0, ret, 0, PROTOCOL_VERSION.length);
        ret[2] = type.getValue();
        ret[3] = (byte)((data.length >> 8) & 0xFF);
        ret[4] = (byte)(data.length & 0xFF);
        System.arraycopy(data, 0, ret, 5, data.length);

        return ret;
    }

    public static ParseResult ParseMessage(byte[] data) {
        if (data.length < 5) {
            return new ParseResult(ParseResult.Result.TOO_SHORT);
        }

        if (data[0] != PROTOCOL_VERSION[0] || data[1] != PROTOCOL_VERSION[1]) {
            return new ParseResult(ParseResult.Result.INVALID_VERSION);
        }

        if (data[2] >= Message.MessageType.MAX_MESSAGE_TYPE.getValue()) {
            return new ParseResult(ParseResult.Result.INVALID_MESSAGE_TYPE);
        }

        int length = (data[3] << 8) | (data[4]);
        if(data.length - 5 < length) {
            return new ParseResult(ParseResult.Result.TOO_SHORT);
        }

        Message msg = new Message();
        msg.type = Message.MessageType.values()[data[2]];
        msg.raw_payload = Arrays.copyOfRange(data, 5, length+5);

        return new ParseResult(ParseResult.Result.OK, msg, length+5);
    }
}
