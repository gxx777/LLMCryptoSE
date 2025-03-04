import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class SignatureExample2 {

    public static byte[] sign(String algorithm, byte[] privateKeyBytes, byte[] message) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(message);

        return signature.sign();
    }

    public static boolean verify(String algorithm, byte[] publicKeyBytes, byte[] message, byte[] signatureBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(message);

        return signature.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        String algorithm = "SHA256withRSA";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();

        String message = "Hello, world!";
        byte[] signature = sign(algorithm, privateKeyBytes, message.getBytes());

        boolean isVerified = verify(algorithm, publicKeyBytes, message.getBytes(), signature);
        System.out.println("Signature verified: " + isVerified);
    }
}