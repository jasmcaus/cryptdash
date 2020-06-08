package EncryptionDecryption;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CryptoMain{
    static Cipher cipher;

    //MAIN FUNCTION --------------------------------------------------------------------------
    public static void main(String[] args) throws Exception {
//        
//        Scanner au=new Scanner(System.in);
//        System.out.println("Enter a password to be encrypted: ");
//        String plainText = au.nextLine();
//        System.out.println("Plain Text Before Encryption: " + plainText);
//        SecretKey secret = generate();
//        String encryptedText = encrypt(plainText, secret);
//        System.out.println("Encrypted Text After Encryption: " + encryptedText);
//
//        String decryptedText = decrypt(plainText, secret);
//        System.out.println("Decrypted Text After Decryption: " + decryptedText);
//        au.close();
          //run("Hello World! ");
    }
    
//    
//    public static void updateMessageField(String messageToBeEncrypted) throws Exception {
//        Dashframe dashframe=new Dashframe();
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(128);
//        SecretKey secretKey = keyGenerator.generateKey();
//        cipher = Cipher.getInstance("AES");
//        //messageToBeEncrypted is an argument of the run() function
//        String encryptedText = encrypt(messageToBeEncrypted, secretKey);
//    }
    

    //ENCRYPT FUNCTION -----------------------------------------------------------------------
    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        byte[] plainTextByte = plainText.getBytes("UTF-8");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        Base64.Encoder encoder = Base64.getEncoder();
        String encryptedText = encoder.encodeToString(encryptedByte);
        return encryptedText;
    } 
}

