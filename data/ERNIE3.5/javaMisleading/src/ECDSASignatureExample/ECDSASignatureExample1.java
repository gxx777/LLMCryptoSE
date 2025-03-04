import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyGenerator;

public class ECDSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 初始化椭圆曲线密钥生成器
//        KeyGenerator keyGen = KeyGenerator.getInstance("EC");
//        keyGen.init(new ECGenParameterSpec("secp256r1"));
//
//        // 生成密钥对
//        KeyPair keyPair = keyGen.generateKeyPair();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();


        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 要签名的消息
        String message = "Hello, this is a message to be signed using ECDSA.";

        // 使用私钥对消息进行签名
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ecdsa.sign();

        // 使用公钥验证签名
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        boolean isValid = ecdsa.verify(signature);

        System.out.println("Signature is valid: " + isValid);
    }
}