import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class AsymmetricEncryption3 {
    private static final String SYMMETRIC_ALGORITHM = "RC4";
    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the symmetric key file
        String inputFile = "symmetric_key.txt";
        String encryptedFile = "encrypted_symmetric_key.txt";
        encryptSymmetricKeyFile(inputFile, encryptedFile, publicKey);

        // Decrypt the symmetric key file
        String decryptedFile = "decrypted_symmetric_key.txt";
        decryptSymmetricKeyFile(encryptedFile, decryptedFile, privateKey);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static void encryptSymmetricKeyFile(String inputFile, String outputFile, PublicKey publicKey) throws Exception {
        byte[] symmetricKeyBytes = Files.readAllBytes(Paths.get(inputFile));
        SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, SYMMETRIC_ALGORITHM);

        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKeyBytes = cipher.doFinal(symmetricKeyBytes);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(encryptedSymmetricKeyBytes);
        }
    }

    private static void decryptSymmetricKeyFile(String inputFile, String outputFile, PrivateKey privateKey) throws Exception {
        byte[] encryptedSymmetricKeyBytes = Files.readAllBytes(Paths.get(inputFile));

        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(encryptedSymmetricKeyBytes);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(decryptedSymmetricKeyBytes);
        }
    }
}