/**
 * SHA1
 */
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Scanner;
public class SHA1 {

    public static void main(String[] args) throws NoSuchAlgorithmException{
        try (Scanner sc = new Scanner(System.in)) {
            System.out.println("Enter text to hash : ");
            String plainText = sc.nextLine();

            Instant startTime = Instant.now();

            MessageDigest md =  MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(plainText.getBytes());

            Instant endTime = Instant.now();

            System.out.println("Hashed Text using SHA-256 : " + bytesToHex(hash));
            
            long elapsedTime = Duration.between(startTime, endTime).toMillis();
            System.out.println("Time to generate the hash is : " +elapsedTime+"ms");
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