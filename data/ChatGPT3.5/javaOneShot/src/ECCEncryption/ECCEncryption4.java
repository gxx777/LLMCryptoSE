import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption4 {

    private static final String EC_ALGORITHM = "EC";
    private static final String SYMMETRIC_ALGORITHM = "AES";

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption4() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM, "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(EC_ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    public SecretKey decryptSymmetricKey(byte[] encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance(EC_ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, SYMMETRIC_ALGORITHM);
    }

    public byte[] encryptData(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public byte[] decryptData(byte[] encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) {
        try {
            ECCEncryption4 eccEncryption = new ECCEncryption4();

            KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();

            byte[] encryptedKey = eccEncryption.encryptSymmetricKey(secretKey);
            SecretKey decryptedKey = eccEncryption.decryptSymmetricKey(encryptedKey);

            byte[] data = "Hello, World!".getBytes();
            byte[] encryptedData = eccEncryption.encryptData(data, decryptedKey);
            byte[] decryptedData = eccEncryption.decryptData(encryptedData, decryptedKey);

            System.out.println("Decrypted data: " + new String(decryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}