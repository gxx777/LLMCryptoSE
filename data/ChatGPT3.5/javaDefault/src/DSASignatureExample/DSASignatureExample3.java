import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DSASignatureExample3 {

    private static final String ALGORITHM = "DSA";
    
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }
    
    public static boolean verifySignature(String message, byte[] signatureToVerify, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureToVerify);
    }
    
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        String message = "Hello, world!";
        
        byte[] signature = signMessage(message, privateKey);
        System.out.println("Signature: " + new String(signature));
        
        boolean verified = verifySignature(message, signature, publicKey);
        System.out.println("Signature verified: " + verified);
    }

}