import java.security.*;
import javax.crypto.*;
import java.io.*;

public class ECCEncryption2 {
    private static final String ALGORITHM = "EC";
    private static final String PROVIDER = "SunEC";
    private static final String TRANSFORMATION = "ECIES";

    public static void main(String[] args) throws Exception {
        // Generate ECC key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        // Encrypt the symmetric key
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal("SymmetricKey".getBytes());

        // Decrypt the symmetric key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);

        // Print the decrypted key
        System.out.println(new String(decryptedKey));
    }
}