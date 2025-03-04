import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DSASignatureExample1 {

    public static void main(String[] args) {
        try {
            // Generate public and private keys
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            
            // Generate signature
            Signature signature = Signature.getInstance("SHA1withDSA");
            signature.initSign(privateKey);
            String msg = "Hello, world!";
            signature.update(msg.getBytes());
            byte[] signatureBytes = signature.sign();
            
            System.out.println("Signature: " + Base64.getEncoder().encodeToString(signatureBytes));
            
            // Verify signature
            Signature verifySignature = Signature.getInstance("SHA1withDSA");
            verifySignature.initVerify(publicKey);
            verifySignature.update(msg.getBytes());
            boolean verified = verifySignature.verify(signatureBytes);
            
            System.out.println("Signature verified: " + verified);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}