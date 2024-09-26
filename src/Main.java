import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/*
    Computer Security Assignment 1: Password Manager
    Lucas Smith and Santiago Castro

 */

public class Main {

    public static void main(String[] args){

        Scanner scanner = new Scanner(System.in);

        try {
            if(createFile()){
                String encryptedPassword = getNewPassword();
                writeToFile(encryptedPassword);
            }else if(!checkPassword()){
                System.out.println("Password is incorrect. Terminating now.");
                System.exit(0);
            }
            mainLoop();
        }
        catch (Exception e) {
            System.out.println("An error occurred.");
            e.printStackTrace();

        }

    }

private static void mainLoop() {
    boolean loop = true;
    Scanner scanner = new Scanner(System.in);
    while (loop) {
        System.out.println("a : Add Password");
        System.out.println("r : Read Password");
        System.out.println("q : Quit ");
        String input = scanner.next();

        switch (input) {
            case "a":
                System.out.print("Enter choice:");
                input = scanner.next();
                System.out.print("\nEnter label for password:");
                input = scanner.next();
                System.out.print("\nEnter password to store:");
                input = scanner.next();
                break;
            case "r":
                System.out.println("Enter the passcode to access your passwords:");
                input = scanner.next();
                if (input.equals("")) {
                    System.out.println("Access granted");


                } else {
                    System.out.println("Access denied");
                    System.exit(0);
                }
                break;
            case "q":
                System.out.println("Exiting program...");
                loop = false;
                System.exit(0);
                break;
            default:
                System.out.println("Invalid input, please try again.");
                break;


        }
    }
}
    private static byte[] generateSalt(){
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }


    private static SecretKeySpec generateKey(String rawPassword, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecureRandom random = new SecureRandom();
        KeySpec spec = new PBEKeySpec(rawPassword.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);


        byte[] encoded =  sharedKey.getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }


    private static String encrypt(String rawPassword, SecretKeySpec key, Cipher cipher) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte [] encryptedData = cipher.doFinal(rawPassword.getBytes());
        return new String(Base64.getEncoder().encode(encryptedData));
    }


    private static String decrypt(String encryptedPass, SecretKeySpec key, Cipher cipher) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte [] decoded = Base64.getDecoder().decode(encryptedPass);
        byte [] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }


    private static boolean createFile() throws IOException {
        try{
            File passwordFile = new File("passwords.txt");
            if (passwordFile.createNewFile()) {
                System.out.println("File created: " + passwordFile.getName());
                return true;
            } else {
                System.out.println("File already exists.");
                return false;
            }
        }
        catch(IOException e){
            System.out.println("An error occurred.");
            e.printStackTrace();
            throw e;
        }
    }


    private static void writeToFile(String siteAndPass) throws IOException {
        try {
            FileWriter myWriter = new FileWriter("passwords.txt");
            myWriter.write(siteAndPass);
            myWriter.close();
            System.out.println("Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
    private static ArrayList<String> readFromFile() throws IOException {
        ArrayList<String> lines = new ArrayList<>();
        try {
            Scanner reader = new Scanner("passwords.txt");
            while (reader.hasNextLine()) {
                lines.add(reader.nextLine());
            }
            return lines;
        } catch (Exception e) {
            System.out.println("An error occurred.");
            throw new RuntimeException(e);
        }
    }

    private static String searchPasswords(String service) throws IOException {
        ArrayList<String> pairs = readFromFile();
        for(String pair: pairs){
            if(pair.contains(service)){
                return pair;
            }
        }
        return "Error: service not found";
    }

    private static String getNewPassword() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Existing password file not found. Creating a new one... \nDone");
        System.out.println("Enter the password you would like to use: ");
        String password = scanner.nextLine();
        byte[] salt = generateSalt();
        SecretKeySpec key = new SecretKeySpec(salt, "AES");
        return encrypt(password, key, Cipher.getInstance("AES"));
    }

    private static boolean checkPassword() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Existing password file found. Reading file...");
        System.out.println("Enter the passcode to access your passwords:");
        String passcode = scanner.nextLine();
        byte[] salt = getSalt();
        SecretKeySpec key = new SecretKeySpec(salt, "AES");
        String encryptedPass = encrypt(passcode, key, Cipher.getInstance("AES"));
        if(encryptedPass.equals(getToken())){
            System.out.println("Welcome!");
            return true;
        }else{
            System.out.println("Wrong password, access denied.");
            return false;
        }
    }

    private static String getEncryptedPass(String service) throws IOException {
        return searchPasswords(service);
    }

    private static byte[] getSalt() throws IOException {
        String saltTokenPair = readFromFile().getFirst();
        String salt = saltTokenPair.substring(0, saltTokenPair.indexOf(":"));
        return Base64.getDecoder().decode(salt);
    }

    private static String getToken() throws IOException {
        String saltTokenPair = readFromFile().getFirst();
        return saltTokenPair.substring(saltTokenPair.indexOf(":") + 1);

    }
}






