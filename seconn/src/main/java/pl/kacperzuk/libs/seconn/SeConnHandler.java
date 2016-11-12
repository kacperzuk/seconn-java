package pl.kacperzuk.libs.seconn;

public interface SeConnHandler {
    void writeData(byte[] data);

    void onDataReceived(byte[] data);

    void onStateChange(SeConn.State prev_state, SeConn.State cur_state);
}
