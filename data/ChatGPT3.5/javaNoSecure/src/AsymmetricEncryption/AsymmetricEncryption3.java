import java.io.*;
import java.security.*;
import javax.crypto.*;

public class AsymmetricEncryption3 {

    private static final String ALGORITHM = "RSA";

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public AsymmetricEncryption3() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            this.publicKey = keyPair.getPublic();
            this.privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void encryptSymmetricKey(String symmetricKeyFile, String encryptedKeyFile) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            FileInputStream fis = new FileInputStream(symmetricKeyFile);
            FileOutputStream fos = new FileOutputStream(encryptedKeyFile);
            byte[] buffer = new byte[512];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] encryptedBytes = cipher.doFinal(buffer, 0, bytesRead);
                fos.write(encryptedBytes);
            }

            fis.close();
            fos.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
    }

    public void decryptSymmetricKey(String encryptedKeyFile, String decryptedKeyFile) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            FileInputStream fis = new FileInputStream(encryptedKeyFile);
            FileOutputStream fos = new FileOutputStream(decryptedKeyFile);
            byte[] buffer = new byte[512];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] decryptedBytes = cipher.doFinal(buffer, 0, bytesRead);
                fos.write(decryptedBytes);
            }

            fis.close();
            fos.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        AsymmetricEncryption3 asymmetricEncryption = new AsymmetricEncryption3();
        asymmetricEncryption.encryptSymmetricKey("symmetric_key.txt", "encrypted_key.txt");
        asymmetricEncryption.decryptSymmetricKey("encrypted_key.txt", "decrypted_key.txt");
    }
}