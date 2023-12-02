import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;
import java.util.Scanner;

public class DSA {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        try (Scanner sc = new Scanner(System.in)) {
            System.out.println("Enter Message : ");
            String plainText = sc.nextLine();

            Instant startTime = Instant.now();

            // Generate key pair
            KeyPair keyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Hash the message
            MessageDigest md =  MessageDigest.getInstance("SHA256");
            byte[] hash = md.digest(plainText.getBytes());

            // Signing with RSA
            Signature sign = Signature.getInstance("SHA256withDSA");
            sign.initSign(privateKey);
            sign.update(hash);
            byte[] digitalSign = sign.sign();

            System.out.println("Digital Signature : " +bytesToHex(digitalSign));

            // Verification
            sign.initVerify(publicKey);
            sign.update(hash);
            boolean verified = sign.verify(digitalSign);

            System.out.println("Signature Verified : "+verified);

            Instant endTime = Instant.now();
            
            long elapsedTime = Duration.between(startTime, endTime).toMillis();
            System.out.println("Time to complete the process is : " +elapsedTime+"ms");
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
