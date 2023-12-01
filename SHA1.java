/**
 * SHA1
 */
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
public class SHA1 {

    public static void main(String[] args) throws NoSuchAlgorithmException{
        try (Scanner sc = new Scanner(System.in)) {
            System.out.println("Enter text to hash : ");
            String plainText = sc.nextLine();


            MessageDigest md =  MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(plainText.getBytes());

            System.out.println("Hashed Text using SHA-256 : " + bytesToHex(hash));
        }
    }
    
    private static String bytesToHex(byte[] hash){
        StringBuilder sb = new StringBuilder(2*hash.length);
        for(byte b:hash){
            sb.append(String.format("%02x", b & 0xff));
        }

        return sb.toString();
    }
}