import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Base64;

public class SignatureExample3 {
    
    private static final String ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    
    public static void generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(2048);
        
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }
    
    public static String signMessage(String message) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        
        byte[] signatureBytes = signature.sign();
        
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
    
    public static boolean verifySignature(String message, String signature) throws Exception {
        Signature sign = Signature.getInstance(SIGNATURE_ALGORITHM);
        sign.initVerify(publicKey);
        sign.update(message.getBytes());
        
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        
        return sign.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        generateKeyPair();

        String originalMessage = "Hello, world!";
        
        String signature = signMessage(originalMessage);
        System.out.println("Signature: " + signature);
        
        boolean isVerified = verifySignature(originalMessage, signature);
        System.out.println("Signature verified: " + isVerified);
    }
}