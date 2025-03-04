//import javax.crypto.Cipher;
//import java.io.*;
//import java.security.KeyFactory;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//
//public class RSAEncryption4 {
//
//    public static void encryptSymmetricKeyFile(String publicKeyFile, String symmetricKeyFile, String encryptedSymmetricKeyFile) throws Exception {
//        // Read the public key from file
//        FileInputStream fis = new FileInputStream(publicKeyFile);
//        byte[] publicKeyBytes = new byte[fis.available()];
//        fis.read(publicKeyBytes);
//        fis.close();
//
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PublicKey publicKey = keyFactory.generatePublic(keySpec);
//
//        // Read the symmetric key from file
//        fis = new FileInputStream(symmetricKeyFile);
//        byte[] symmetricKeyBytes = new byte[fis.available()];
//        fis.read(symmetricKeyBytes);
//        fis.close();
//
//        // Encrypt the symmetric key with RSA
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encryptedSymmetricKeyBytes = cipher.doFinal(symmetricKeyBytes);
//
//        // Write the encrypted symmetric key to file
//        FileOutputStream fos = new FileOutputStream(encryptedSymmetricKeyFile);
//        fos.write(encryptedSymmetricKeyBytes);
//        fos.close();
//    }
//
//    public static void decryptSymmetricKeyFile(String privateKeyFile, String encryptedSymmetricKeyFile, String decryptedSymmetricKeyFile) throws Exception {
//        // Read the private key from file
//        FileInputStream fis = new FileInputStream(privateKeyFile);
//        byte[] privateKeyBytes = new byte[fis.available()];
//        fis.read(privateKeyBytes);
//        fis.close();
//
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
//
//        // Read the encrypted symmetric key from file
//        fis = new FileInputStream(encryptedSymmetricKeyFile);
//        byte[] encryptedSymmetricKeyBytes = new byte[fis.available()];
//        fis.read(encryptedSymmetricKeyBytes);
//        fis.close();
//
//        // Decrypt the encrypted symmetric key with RSA
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(encryptedSymmetricKeyBytes);
//
//        // Write the decrypted symmetric key to file
//        FileOutputStream fos = new FileOutputStream(decryptedSymmetricKeyFile);
//        fos.write(decryptedSymmetricKeyBytes);
//        fos.close();
//    }
//
//    public static void main(String[] args) {
//        try {
//            String publicKeyFile = "publicKey.pem";
//            String privateKeyFile = "privateKey.pem";
//            String symmetricKeyFile = "symmetricKey.txt";
//            String encryptedSymmetricKeyFile = "encryptedSymmetricKey.txt";
//            String decryptedSymmetricKeyFile = "decryptedSymmetricKey.txt";
//
//            // Generate and save public/private keys
//            RSAKeyPairGenerator.generateRSAKeyPair(publicKeyFile, privateKeyFile);
//
//            // Generate and save symmetric key
//            SymmetricKeyGenerator.generateSymmetricKey(symmetricKeyFile);
//
//            // Encrypt symmetric key file
//            encryptSymmetricKeyFile(publicKeyFile, symmetricKeyFile, encryptedSymmetricKeyFile);
//
//            // Decrypt symmetric key file
//            decryptSymmetricKeyFile(privateKeyFile, encryptedSymmetricKeyFile, decryptedSymmetricKeyFile);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}