import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCEncryption2 {
    
    public static void main(String[] args) throws Exception {
        
        Security.addProvider(new BouncyCastleProvider());
        
        // Generate ECC Key Pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // Generate and encrypt symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey symmetricKey = keyGenerator.generateKey();
        
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getEncoded());
        
        // Decrypt symmetric key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);
        
        // Print encrypted and decrypted symmetric keys
        System.out.println("Symmetric Key: " + symmetricKey);
        System.out.println("Encrypted Symmetric Key: " + new String(encryptedSymmetricKey));
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));
    }
}