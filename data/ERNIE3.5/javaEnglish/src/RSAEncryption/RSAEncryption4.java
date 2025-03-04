import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RSAEncryption4 {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public void encryptSymmetricKeyFile(String symmetricKeyFile, String encryptedSymmetricKeyFile) throws Exception {
        File symmetricKeyFileInput = new File(symmetricKeyFile);
        File encryptedSymmetricKeyFileOutput = new File(encryptedSymmetricKeyFile);

        try (FileInputStream fis = new FileInputStream(symmetricKeyFileInput);
             FileOutputStream fos = new FileOutputStream(encryptedSymmetricKeyFileOutput)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            while ((bytesRead = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }

            byte[] symmetricKey = baos.toByteArray();
            byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey);

            fos.write(encryptedSymmetricKey);
        }
    }

    public void decryptSymmetricKeyFile(String encryptedSymmetricKeyFile, String decryptedSymmetricKeyFile) throws Exception {
        File encryptedSymmetricKeyFileInput = new File(encryptedSymmetricKeyFile);
        File decryptedSymmetricKeyFileOutput = new File(decryptedSymmetricKeyFile);

        try (FileInputStream fis = new FileInputStream(encryptedSymmetricKeyFileInput);
             FileOutputStream fos = new FileOutputStream(decryptedSymmetricKeyFileOutput)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            while ((bytesRead = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }

            byte[] encryptedSymmetricKey = baos.toByteArray();
            byte[] decryptedSymmetricKey = decryptSymmetricKey(encryptedSymmetricKey);

            fos.write(decryptedSymmetricKey);
        }
    }

    public static void main(String[] args) {
        try {
            RSAEncryption4 rsaEncryption = new RSAEncryption4();

            // Encrypt symmetric key file
            String symmetricKeyFile = "path/to/symmetric_key_file";
            String encryptedSymmetricKeyFile = "path/to/encrypted_symmetric_key_file";
            rsaEncryption.encryptSymmetricKeyFile(symmetricKeyFile, encryptedSymmetricKeyFile);

            // Decrypt symmetric key file
            String decryptedSymmetricKeyFile = "path/to/decrypted_symmetric_key_file";
            rsaEncryption.decryptSymmetricKeyFile(encryptedSymmetricKeyFile, decryptedSymmetricKeyFile);

            System.out.println("Symmetric key file has been successfully encrypted and decrypted.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}