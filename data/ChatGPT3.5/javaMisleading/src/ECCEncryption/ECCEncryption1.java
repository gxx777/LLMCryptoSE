//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.Security;
//
//import javax.crypto.Cipher;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//
//public class ECCEncryption1 {
//
//    static {
//        Security.addProvider(new BouncyCastleProvider());
//    }
//
//    public static void main(String[] args) throws Exception {
//
//        // Generate ECC key pair
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
//        keyGen.initialize(256);
//        KeyPair keyPair = keyGen.generateKeyPair();
//
//        PublicKey publicKey = keyPair.getPublic();
//        PrivateKey privateKey = keyPair.getPrivate();
//
//        // Encrypt symmetric key file using ECC public key
//        Cipher encCipher = Cipher.getInstance("ECIES", "BC");
//        encCipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encryptedSymmetricKeyFile = encCipher.doFinal(symmKeyFileBytes);
//
//        // Decrypt symmetric key file using ECC private key
//        Cipher decCipher = Cipher.getInstance("ECIES", "BC");
//        decCipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] decryptedSymmetricKeyFile = decCipher.doFinal(encryptedSymmetricKeyFile);
//
//        // Use decrypted symmetric key file for decryption of actual data
//
//    }
//}