package pl.kacperzuk.libs.seconn;

public class KeyPairBytes {
    public byte[] private_key;
    public byte[] public_key;

    public KeyPairBytes(byte[] priv_key, byte[] pub_key) {
        private_key = priv_key;
        public_key = pub_key;
    }
}
