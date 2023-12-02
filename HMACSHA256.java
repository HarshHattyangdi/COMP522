import java.time.Duration;
import java.time.Instant;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACSHA256 {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter Message : ");
        String plainText = sc.nextLine();

        String secretKey = "AbC#$123";
        
        Instant startTime = Instant.now();
        
        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        hmacSha256.init(secretKeySpec);
        byte[] hmac = hmacSha256.doFinal(plainText.getBytes());

        Instant endTime = Instant.now();


        System.out.println("HMAC-SHA256 : " +bytesToHex(hmac));
        long elapsedTime = Duration.between(startTime, endTime).toMillis();
        System.out.println("Time to generate the hash is : " +elapsedTime+"ms");
    }

    private static String bytesToHex(byte[] hash){
        StringBuilder sb = new StringBuilder(2*hash.length);
        for(byte b:hash){
            sb.append(String.format("%02x", b & 0xff));
        }

        return sb.toString();
    }

}
