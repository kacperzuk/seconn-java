package pl.kacperzuk.libs.seconn;

/**
 * Created by kaz on 11.11.16.
 */

public interface SeConnHandler {
    void writeData(byte[] data);
    void onDataReceived(byte[] data);
    void onStateChange(SeConn.State prev_state, SeConn.State cur_state);
}
