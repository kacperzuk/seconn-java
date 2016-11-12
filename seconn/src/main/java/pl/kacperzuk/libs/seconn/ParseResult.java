package pl.kacperzuk.libs.seconn;


public class ParseResult {
    public enum Result {
        OK,
        TOO_SHORT,
        INVALID_VERSION,
        INVALID_MESSAGE_TYPE;
    }

    private final Result result;
    private final Message message;
    private final int bytesConsumed;

    ParseResult(Result res) {
        this(res, null, 0);
    }

    ParseResult(Result res, Message msg, int bytes) {
        result = res;
        message = msg;
        bytesConsumed = bytes;
    }

    public Result getResult() {
        return result;
    }

    public Message getMessage() {
        return message;
    }

    public int getBytesConsumed() {
        return bytesConsumed;
    }
}
