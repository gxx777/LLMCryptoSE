import java.util.Base64;

public class PasswordProtection3 {
    private String password;

    public PasswordProtection3(String password) {
        this.password = encodePassword(password);
    }

    public String getPassword() {
        return decodePassword(this.password);
    }

    private String encodePassword(String password) {
        return Base64.getEncoder().encodeToString(password.getBytes());
    }

    private String decodePassword(String encodedPassword) {
        return new String(Base64.getDecoder().decode(encodedPassword));
    }
}