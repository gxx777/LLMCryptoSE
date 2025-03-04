import java.security.*;
import java.util.Base64;

public class DSASignatureExample4 {
    private static final String SIGNING_ALGORITHM = "SHA256withDSA";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        // Sign the message
        String message = "Hello, World!";
        Signature dsa = Signature.getInstance(SIGNING_ALGORITHM);
        dsa.initSign(priv);
        byte[] strByte = message.getBytes("UTF8");
        dsa.update(strByte);
        byte[] realSig = dsa.sign();
        String signed = Base64.getEncoder().encodeToString(realSig);
        System.out.println("Signature: " + signed);

        // Verify the signature
        Signature sig = Signature.getInstance(SIGNING_ALGORITHM);
        sig.initVerify(pub);
        sig.update(strByte);
        boolean verifies = sig.verify(realSig);
        System.out.println("signature verifies: " + verifies);
    }
}