import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.security.*;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;

public class ECDSASignatureExample1 {

    static {
        // 添加Bouncy Castle作为安全提供者
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // 生成ECDSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 原始消息
        String message = "Hello, ECDSA!";

        // 签名
        byte[] signature = sign(message.getBytes(), privateKey);
        System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(signature));

        // 验签
        boolean isValid = verify(message.getBytes(), signature, publicKey);
        System.out.println("Signature valid: " + isValid);
    }

    public static byte[] sign(byte[] message, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA", "BC");
        signer.initSign(privateKey);
        signer.update(message);
        return signer.sign();
    }

    public static boolean verify(byte[] message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(publicKey);
        verifier.update(message);
        return verifier.verify(signature);
    }
}