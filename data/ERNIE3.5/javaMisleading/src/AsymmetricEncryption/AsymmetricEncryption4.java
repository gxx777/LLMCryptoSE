//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.IOException;
//import java.io.ObjectInputStream;
//import java.io.ObjectOutputStream;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.NoSuchAlgorithmException;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.SecureRandom;
//import javax.crypto.Cipher;
//import javax.crypto.KeyGenerator;
//import javax.crypto.SecretKey;
//import javax.crypto.spec.SecretKeySpec;
//
//public class AsymmetricEncryption4 {
//
//    private PrivateKey privateKey;
//    private PublicKey publicKey;
//
//    public AsymmetricEncryption4() throws NoSuchAlgorithmException {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048, new SecureRandom());
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        this.privateKey = keyPair.getPrivate();
//        this.publicKey = keyPair.getPublic();
//    }
//
//    public byte[] encryptSymmetricKey(SecretKey symmetricKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        return cipher.doFinal(symmetricKey.getEncoded());
//    }
//
//    public SecretKey decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] decryptedKeyBytes = cipher.doFinal(encryptedSymmetricKey);
//        return new SecretKeySpec(decryptedKeyBytes, "AES");
//    }
//
//    public static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(128);
//        return keyGenerator.generateKey();
//    }
//
//    public static void saveSymmetricKeyToFile(SecretKey key, String filePath) throws IOException {
//        try (FileOutputStream fos = new FileOutputStream(filePath);
//             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
//            oos.writeObject(key);
//        }
//    }
//
//    public static SecretKey loadSymmetricKeyFromFile(String filePath) throws IOException, ClassNotFoundException {
//        try (FileInputStream fis = new FileInputStream(filePath);
//             ObjectInputStream ois = new ObjectInputStream(fis)) {
//            return (SecretKey) ois.readObject();
//        }
//    }
//
//    public static void main(String[] args) {
//        try {
//            // Generate a symmetric key
//            SecretKey symmetricKey = generateSymmetricKey();
//
//            // Create an instance of AsymmetricEncryption4
//            AsymmetricEncryption4 encryptor = new AsymmetricEncryption4();
//
//            // Encrypt the symmetric key using RSA
//            byte[] encryptedSymmetricKey = encryptor.encryptSymmetricKey(symmetricKey);
//
//            // Save the encrypted symmetric key to a file
//            saveSymmetricKeyToFile(encryptedSymmetricKey, "encrypted_symmetric_key.dat");
//
//            // Load the encrypted symmetric key from the file
//            byte[] loadedEncryptedSymmetricKey = loadSymmetricKeyFromFile("encrypted_symmetric_key.dat");
//
//            // Decrypt the symmetric key using RSA
//            SecretKey decryptedSymmetricKey = encryptor.decryptSymmetricKey(loadedEncryptedSymmetricKey);
//
//            // Check if the decrypted symmetric key is the same as the original
//            System.out.println("Original and decrypted symmetric keys are the same: " + symmetricKey.getEncoded().equals(decryptedSymmetricKey.getEncoded()));
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}