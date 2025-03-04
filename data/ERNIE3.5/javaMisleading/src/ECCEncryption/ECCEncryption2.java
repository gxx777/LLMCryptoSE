import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECCEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption2() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime256v1");
        keyGen.initialize(ecSpec, new SecureRandom());
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public void savePrivateKeyToFile(String filePath) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("eccPrivateKey", privateKey, "password".toCharArray(), null);
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            ks.store(fos, "password".toCharArray());
        }
    }

    public void loadPrivateKeyFromFile(String filePath) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(filePath)) {
            ks.load(fis, "password".toCharArray());
        }
        KeyStore.ProtectionParameter protParam =
                new KeyStore.PasswordProtection("password".toCharArray());
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("eccPrivateKey", protParam);
        this.privateKey = keyEntry.getPrivateKey();
    }

    public static void main(String[] args) {
        try {
            ECCEncryption2 ecc = new ECCEncryption2();

            // Generate a symmetric key to encrypt/decrypt
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] symmetricKey = secretKey.getEncoded();

            // Encrypt the symmetric key
            byte[] encryptedSymmetricKey = ecc.encryptSymmetricKey(symmetricKey);

            // Decrypt the symmetric key
            byte[] decryptedSymmetricKey = ecc.decryptSymmetricKey(encryptedSymmetricKey);

            // Save and load private key to file
            String privateKeyFile = "private_key.jks";
            ecc.savePrivateKeyToFile(privateKeyFile);
            ecc.loadPrivateKeyFromFile(privateKeyFile);

            // Verify that the decrypted symmetric key matches the original
            if (java.util.Arrays.equals(symmetricKey, decryptedSymmetricKey)) {
                System.out.println("Symmetric key encryption and decryption successful!");
            } else {
                System.out.println("Symmetric key encryption and decryption failed!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}