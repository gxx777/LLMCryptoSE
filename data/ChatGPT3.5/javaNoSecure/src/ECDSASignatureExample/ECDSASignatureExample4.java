import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class ECDSASignatureExample4 {
    
    public static void main(String[] args) throws Exception {
        
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Get private key and public key
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Create a signature object with the ECDSA algorithm
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        
        // Sign the message
        String message = "Hello, world!";
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes());
        byte[] signature = ecdsa.sign();
        String base64Signature = Base64.getEncoder().encodeToString(signature);
        System.out.println("Signature: " + base64Signature);
        
        // Verify the signature
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes());
        boolean verified = ecdsa.verify(signature);
        System.out.println("Signature verified: " + verified);
    }
}