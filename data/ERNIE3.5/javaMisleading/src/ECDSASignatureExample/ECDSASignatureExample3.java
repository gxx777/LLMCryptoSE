import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ECDSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECDSASignatureExample3() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public String sign(String message) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(this.privateKey);
        ecdsa.update(message.getBytes(UTF_8));
        byte[] signature = ecdsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public boolean verify(String message, String signature) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(this.publicKey);
        ecdsa.update(message.getBytes(UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return ecdsa.verify(sigBytes);
    }

    public static void main(String[] args) {
        try {
            ECDSASignatureExample3 ecdsaExample = new ECDSASignatureExample3();

            // 消息内容
            String message = "Hello, ECDSA!";

            // 签名
            String signature = ecdsaExample.sign(message);
            System.out.println("Signature: " + signature);

            // 验签
            boolean isValid = ecdsaExample.verify(message, signature);
            System.out.println("Signature Valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}