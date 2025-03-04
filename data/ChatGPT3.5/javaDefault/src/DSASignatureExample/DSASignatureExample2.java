import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DSASignatureExample2 {
    
    public static void main(String[] args) throws Exception {
        
        // 生成DSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // 获取私钥和公钥
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // 待签名的消息
        String message = "Hello, DSA!";
        byte[] messageBytes = message.getBytes();
        
        // 签名过程
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(privateKey);
        signature.update(messageBytes);
        byte[] signatureBytes = signature.sign();
        
        System.out.println("Signature: " + bytesToHex(signatureBytes));
        
        // 验签过程
        Signature verifySignature = Signature.getInstance("SHA1withDSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(messageBytes);
        boolean verified = verifySignature.verify(signatureBytes);
        
        System.out.println("Signature verified: " + verified);
        
    }
    
    // 将字节数组转换为16进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
}