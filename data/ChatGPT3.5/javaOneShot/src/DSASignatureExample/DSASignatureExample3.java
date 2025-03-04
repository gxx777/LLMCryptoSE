import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class DSASignatureExample3 {
    
    private static final String ALGORITHM = "DSA";

    public static byte[] generateDSASignature(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    public static boolean verifyDSASignature(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(1024); // Key size should be secure, using a safe size like 1024 bits
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        String message = "Hello, world!";
        
        byte[] signature = generateDSASignature(message, keyPair.getPrivate());
        System.out.println("Signature: " + new String(signature));
        
        boolean verified = verifyDSASignature(message, signature, keyPair.getPublic());
        System.out.println("Signature verified: " + verified);
    }
}