import java.security.*;
import java.util.Base64;

public class DSASignatureExample1 {
    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstanceStrong();
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        // Sign the message
        String message = "Hello, World!";
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initSign(priv);
        byte[] strByte = message.getBytes("UTF8");
        dsa.update(strByte);
        byte[] realSig = dsa.sign();
        String signature = Base64.getEncoder().encodeToString(realSig);
        System.out.println("Signature: " + signature);

        // Verify the message
        Signature sig = Signature.getInstance("SHA1withDSA");
        sig.initVerify(pub);
        sig.update(strByte);
        boolean verifies = sig.verify(realSig);
        System.out.println("signature verifies: " + verifies);
    }
}