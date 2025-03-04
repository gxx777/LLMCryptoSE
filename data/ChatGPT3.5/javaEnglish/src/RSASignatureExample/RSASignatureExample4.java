import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class RSASignatureExample4 {

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        
        // Generate key pair
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Sign the message
        byte[] signature = sign(message, privateKey);
        System.out.println("Signature: " + new String(signature));
        
        // Verify the signature
        boolean isVerified = verify(message, signature, publicKey);
        System.out.println("Signature verified: " + isVerified);
    }
    
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
    
    public static byte[] sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }
    
    public static boolean verify(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifiedSignature = Signature.getInstance("SHA256withRSA");
        verifiedSignature.initVerify(publicKey);
        verifiedSignature.update(message.getBytes());
        return verifiedSignature.verify(signature);
    }
}