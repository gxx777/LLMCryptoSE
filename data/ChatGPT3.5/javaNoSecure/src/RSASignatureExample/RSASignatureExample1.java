import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class RSASignatureExample1 {
    
    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Create a signature object
        Signature signature = Signature.getInstance("SHA256withRSA");
        
        // Initialize the signature object with the private key for signing
        signature.initSign(privateKey);
        
        // Data to be signed
        byte[] data = "Hello, world!".getBytes();
        
        // Perform the signing
        signature.update(data);
        byte[] signatureBytes = signature.sign();
        
        System.out.println("Signature generated: " + new String(signatureBytes));
        
        // Initialize the signature object with the public key for verification
        signature.initVerify(publicKey);
        
        // Verify the signature
        signature.update(data);
        boolean verified = signature.verify(signatureBytes);
        
        if (verified) {
            System.out.println("Signature verified!");
        } else {
            System.out.println("Signature verification failed!");
        }
    }
}