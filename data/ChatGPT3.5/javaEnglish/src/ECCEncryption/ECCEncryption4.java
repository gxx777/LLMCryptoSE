import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class ECCEncryption4 {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String ECC_ALGORITHM = "EC";
    private static final int KEY_SIZE = 256;

    private KeyPair generateECCKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ECC_ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    private byte[] encryptSymmetricKey(Key key, Key publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ECC_ALGORITHM);
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(key);
    }

    private Key decryptSymmetricKey(byte[] encryptedKey, Key privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ECC_ALGORITHM);
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return cipher.unwrap(encryptedKey, ALGORITHM, Cipher.SECRET_KEY);
    }

    public byte[] encryptFile(byte[] fileData, Key publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        SecretKeySpec secretKey = new SecretKeySpec(generateECCKeys().getEncoded(), ALGORITHM);
        KeyPair keyPair = generateECCKeys();
        SecretKeySpec secretKey = new SecretKeySpec(keyPair.getPrivate().getEncoded(), ALGORITHM);
        byte[] encryptedKey = encryptSymmetricKey(secretKey, publicKey);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(fileData);

        byte[] fileEncryption = new byte[encryptedKey.length + encryptedData.length];
        System.arraycopy(encryptedKey, 0, fileEncryption, 0, encryptedKey.length);
        System.arraycopy(encryptedData, 0, fileEncryption, encryptedKey.length, encryptedData.length);

        return fileEncryption;
    }

    public byte[] decryptFile(byte[] fileEncryption, Key privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedKey = new byte[KEY_SIZE / 8];
        System.arraycopy(fileEncryption, 0, encryptedKey, 0, encryptedKey.length);

        byte[] encryptedData = new byte[fileEncryption.length - encryptedKey.length];
        System.arraycopy(fileEncryption, encryptedKey.length, encryptedData, 0, encryptedData.length);

        Key secretKey = decryptSymmetricKey(encryptedKey, privateKey);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }
}