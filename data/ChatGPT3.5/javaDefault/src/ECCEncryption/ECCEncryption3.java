import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class ECCEncryption3 {
    
    private static final String ALGORITHM = "EC";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final String MODE = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }
    
    public byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getEncoded());
        return encryptedSymmetricKey;
    }
    
    public SecretKey decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(encryptedSymmetricKey);
        return new SecretKeySpec(decryptedSymmetricKeyBytes, 0, decryptedSymmetricKeyBytes.length, SYMMETRIC_ALGORITHM);
    }
}