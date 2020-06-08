//package EncryptionDecryption;
//
//import java.security.Security;
//import javax.crypto.Cipher;
//import javax.crypto.KeyGenerator;
//import javax.crypto.SecretKey;
//
//public class Encryption {
//	private static Cipher cipher = null;
//        
//        public static void main(String [] args) throws Exception{
//            //The main function
//            //updateMessageFields("Hello World! ");
//        }
//
////	public static void updateMessageFields(String messageToBeEncrypted) throws Exception {
////                Dashframe dashframe=new Dashframe();
////		// uncomment the following line to add the Provider of choice
////		//Security.addProvider(new com.sun.crypto.provider.SunJCE());
////
////		KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
////		// keysize must be equal to 112 or 168 for this provider
////		keyGenerator.init(168);
////		SecretKey secretKey = keyGenerator.generateKey();
////		cipher = Cipher.getInstance("DESede");
////
//////		String plainText = "Java Cryptography Extension";
//////		System.out.println("Plain Text Before Encryption: " + plainText);
////
////		byte[] plainTextByte = messageToBeEncrypted.getBytes("UTF8");
////		byte[] encryptedBytes = encrypt(plainTextByte, secretKey);
////                //Encrypted Text
////		String encryptedText = new String(encryptedBytes, "UTF8");
////                //Decrypted Text
////		byte[] decryptedBytes = decrypt(encryptedBytes, secretKey);
////		String decryptedText = new String(decryptedBytes, "UTF8");
////                //Updating the fields 
////                System.out.println(encryptedText + "\t\t\t\t" + decryptedText);
////                //dashframe.updateOutputs("Hello ", "Hello");
////        }
//
//	public static byte[] encrypt(byte[] plainTextByte, SecretKey secretKey)
//			throws Exception {
//		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//		byte[] encryptedBytes = cipher.doFinal(plainTextByte);
//		return encryptedBytes;
//	}
//
//	public static byte[] decrypt(byte[] encryptedBytes, SecretKey secretKey)
//			throws Exception {
//		cipher.init(Cipher.DECRYPT_MODE, secretKey);
//		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
//		return decryptedBytes;
//	}
//}