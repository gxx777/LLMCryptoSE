import java.security.*;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample3 {

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        // 要签名的消息
        String message = "这是一个需要签名的消息";

        // 使用私钥进行签名
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(message.getBytes(UTF_8));
        byte[] signature = privateSignature.sign();

        // 使用公钥进行验签
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(message.getBytes(UTF_8));
        boolean isVerified = publicSignature.verify(signature);

        System.out.println("签名结果: " + Arrays.toString(signature));
        System.out.println("验签结果: " + isVerified);
    }
}