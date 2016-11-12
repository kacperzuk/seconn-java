package pl.kacperzuk.libs.seconn;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Crypto {
    private ECPrivateKey ourECPrivKey;
    private ECPublicKey ourECPubKey;
    private byte[] encKey;
    private byte[] macKey;

    Crypto(KeyPairBytes keyPairBytes) {
        if (keyPairBytes == null) {
            KeyPair kp = generateKeyPair();
            ourECPrivKey = (ECPrivateKey) kp.getPrivate();
            ourECPubKey = (ECPublicKey) kp.getPublic();
        } else {
            ourECPrivKey = parsePrivateKey(keyPairBytes.private_key);
            ourECPubKey = parsePublicKey(keyPairBytes.public_key);
        }
    }

    private byte[] calculateSignature(byte[] data, byte[] mac_key) {
        SecretKeySpec skeySpec = new SecretKeySpec(mac_key, "AES");
        Cipher cipher = null;
        byte[] encrypted = null;

        try {
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
            byte[] iv = new byte[16];
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            encrypted = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }

        return Arrays.copyOfRange(encrypted, encrypted.length - 16, encrypted.length);
    }

    boolean checkMac(byte[] payload) {
        byte[] mac = Arrays.copyOfRange(payload, 0, 16);
        byte[] data = Arrays.copyOfRange(payload, 16, payload.length);
        return MessageDigest.isEqual(calculateSignature(data, macKey), mac);
    }

    KeyPairBytes getKeyPair() {
        return new KeyPairBytes(formatPrivateKey(ourECPrivKey), formatPublicKey(ourECPubKey));
    }

    byte[] encryptThenMac(byte[] data) {
        byte[] ciphertext = encryptData(data, encKey);
        byte[] mac = calculateSignature(ciphertext, macKey);

        byte[] ret = new byte[mac.length + ciphertext.length];
        System.arraycopy(mac, 0, ret, 0, mac.length);
        System.arraycopy(ciphertext, 0, ret, mac.length, ciphertext.length);
        return ret;
    }

    private byte[] xor_block(byte[] a, byte[] b) {
        byte[] ret = new byte[16];
        for (int i = 0; i < 16; i++) {
            ret[i] = (byte) (a[i] ^ b[i]);
        }
        return ret;
    }

    byte[] decrypt(byte[] payload) {
        byte[] encrypted = Arrays.copyOfRange(payload, 16, payload.length);
        SecretKeySpec skeySpec = new SecretKeySpec(encKey, "AES");
        Cipher cipher = null;
        byte[] decrypted = null;

        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            byte[] iv = new byte[16];
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            decrypted = cipher.doFinal(encrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return Arrays.copyOfRange(decrypted, 16, decrypted.length);
    }

    private byte[] encryptData(byte[] data, byte[] enc_key) {
        SecretKeySpec skeySpec = new SecretKeySpec(enc_key, "AES");
        Cipher cipher = null;
        byte[] encrypted = null;
        byte[] extendedData = new byte[data.length + 16];
        byte[] randBlock = new byte[16];
        new SecureRandom().nextBytes(randBlock);
        System.arraycopy(randBlock, 0, extendedData, 0, 16);
        System.arraycopy(data, 0, extendedData, 16, data.length);

        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            byte[] iv = new byte[16];
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            encrypted = cipher.doFinal(extendedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    private byte[] encryptBlock(byte[] data, byte[] key) {
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = null;
        byte[] encrypted = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            encrypted = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    private byte[] extractMACKey(byte[] secret) {
        return Arrays.copyOfRange(secret, 16, 32);
    }

    private byte[] extractEncKey(byte[] secret) {
        return Arrays.copyOfRange(secret, 0, 16);
    }

    private byte[] formatPrivateKey(ECPrivateKey pkey) {
        byte[] ret = new byte[32];
        byte[] tmp = pkey.getS().toByteArray();

        if (tmp.length <= 32)
            System.arraycopy(tmp, 0, ret, 32 - tmp.length, tmp.length);
        else
            System.arraycopy(tmp, tmp.length - 32, ret, 0, 32);

        return ret;
    }

    private byte[] formatPublicKey(ECPublicKey pkey) {
        ECPoint point = pkey.getW();
        byte[] ret = new byte[64];
        byte[] partX = point.getAffineX().toByteArray();
        byte[] partY = point.getAffineY().toByteArray();

        if (partX.length <= 32)
            System.arraycopy(partX, 0, ret, 32 - partX.length, partX.length);
        else
            System.arraycopy(partX, partX.length - 32, ret, 0, 32);

        if (partY.length <= 32)
            System.arraycopy(partY, 0, ret, 64 - partY.length, partY.length);
        else
            System.arraycopy(partY, partY.length - 32, ret, 32, 32);

        return ret;
    }

    private KeyPair generateKeyPair() {
        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            kpg.initialize(ecParamSpec);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return kpg.generateKeyPair();
    }

    private ECParameterSpec getParameterSpec() {
        return ((ECPublicKey) generateKeyPair().getPublic()).getParams();
    }

    private ECPrivateKey parsePrivateKey(byte[] pkey) {
        KeyFactory eckf;
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        byte[] x_bytes = Arrays.copyOfRange(pkey, 0, 32);
        byte[] y_bytes = Arrays.copyOfRange(pkey, 32, 64);
        ECPoint point = new ECPoint(new BigInteger(1, x_bytes), new BigInteger(1, y_bytes));
        ECParameterSpec ecParamSpec = getParameterSpec();
        ECPrivateKey ecPrivateKey = null;

        try {
            ecPrivateKey = (ECPrivateKey) eckf.generatePrivate(new ECPrivateKeySpec(new BigInteger(1, pkey), ecParamSpec));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return ecPrivateKey;
    }

    private ECPublicKey parsePublicKey(byte[] pkey) {
        KeyFactory eckf;
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        byte[] x_bytes = Arrays.copyOfRange(pkey, 0, 32);
        byte[] y_bytes = Arrays.copyOfRange(pkey, 32, 64);
        ECPoint point = new ECPoint(new BigInteger(1, x_bytes), new BigInteger(1, y_bytes));
        ECParameterSpec ecParamSpec = getParameterSpec();
        ECPublicKey ecPublicKey = null;
        try {
            ecPublicKey = (ECPublicKey) eckf.generatePublic(new ECPublicKeySpec(point, ecParamSpec));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return ecPublicKey;
    }

    public void generateSecret(byte[] pkey) throws InvalidKeyException {
        generateSecret(ourECPrivKey, parsePublicKey(pkey));
    }

    public void generateSecret(ECPublicKey pkey) throws InvalidKeyException {
        generateSecret(ourECPrivKey, pkey);
    }

    private void generateSecret(ECPrivateKey privkey, ECPublicKey pubkey) throws InvalidKeyException {
        KeyAgreement aKA;
        try {
            aKA = KeyAgreement.getInstance("ECDH");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
        try {
            aKA.init(privkey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return;
        }

        aKA.doPhase(pubkey, true);
        try {
            byte[] secret = MessageDigest.getInstance("SHA-256").digest(aKA.generateSecret());
            encKey = extractEncKey(secret);
            macKey = extractMACKey(secret);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    byte[] getPubKey() {
        return formatPublicKey(ourECPubKey);
    }
}
