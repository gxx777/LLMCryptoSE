public class PasswordProtection3 {

    private String password;

    public PasswordProtection3(String password) {
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean authenticate(String inputPassword) {
        return password.equals(inputPassword);
    }

    public static void main(String[] args) {
        PasswordProtection3 passwordProtection = new PasswordProtection3("password123");

        // Retrieving password
        String savedPassword = passwordProtection.getPassword();
        System.out.println("Saved password: " + savedPassword);

        // Authenticating with incorrect password
        boolean wrongPassword = passwordProtection.authenticate("incorrect123");
        System.out.println("Authentication with incorrect password: " + wrongPassword);

        // Authenticating with correct password
        boolean correctPassword = passwordProtection.authenticate("password123");
        System.out.println("Authentication with correct password: " + correctPassword);

        // Changing password
        passwordProtection.setPassword("newpassword456");
        System.out.println("Password changed successfully.");
    }
}