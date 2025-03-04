import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        
        // Generate key pairs
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Get private and public keys
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Sign the message
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        
        System.out.println("Digital Signature: " + Base64.getEncoder().encodeToString(signatureBytes));
        
        // Verify the signature
        Signature verification = Signature.getInstance("SHA256withDSA");
        verification.initVerify(publicKey);
        verification.update(message.getBytes());
        boolean isVerified = verification.verify(signatureBytes);
        
        System.out.println("Signature verified: " + isVerified);
    }
}