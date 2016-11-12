package pl.kacperzuk.libs.seconn;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * Created by kaz on 12.11.16.
 */

public class KeyPairBytes {
    public byte[] private_key;
    public byte[] public_key;

    public KeyPairBytes(byte[] priv_key, byte[] pub_key) {
        private_key = priv_key;
        public_key = pub_key;
    }
}
