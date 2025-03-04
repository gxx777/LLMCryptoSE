import java.security.*;

public class DSASignatureExample4 {
    
    private static Signature signature;
    private static KeyPair keyPair;

    static {
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(1024, secureRandom);
            keyPair = keyPairGenerator.generateKeyPair();
            signature = Signature.getInstance("SHA1withDSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static byte[] signData(byte[] data) {
        try {
            signature.initSign(keyPair.getPrivate());
            signature.update(data);
            return signature.sign();
        } catch (InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verifySignature(byte[] data, byte[] signatureBytes) {
        try {
            signature.initVerify(keyPair.getPublic());
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) {
        String message = "Hello, World!";
        byte[] data = message.getBytes();
        byte[] signature = signData(data);

        if (signature != null) {
            System.out.println("Signature: " + new String(signature));

            boolean verified = verifySignature(data, signature);
            System.out.println("Signature verified: " + verified);
        }
    }
}