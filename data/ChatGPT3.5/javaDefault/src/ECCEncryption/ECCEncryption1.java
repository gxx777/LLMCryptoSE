import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class ECCEncryption1 {
    
    public static void main(String[] args) throws Exception {
        
        // Generate ECC key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecParamSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Get public and private keys
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Generate symmetric key file (dummy key for demonstration only)
        byte[] symmetricKey = "This is a secret key".getBytes();
        
        // Encrypt symmetric key with public key
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey);
        
        // Decrypt symmetric key with private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        
        // Print decrypted symmetric key
        System.out.println(new String(decryptedKey));
    }
}