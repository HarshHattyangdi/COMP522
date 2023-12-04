/*
A. Lisitsa, 2019 The code below was 
taken  from 
https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex

and slightly modified in order to compile without errors. 

In particular: 

- "try" and "catch" blocks ,lines 138-148 below,  were commented out, as the variables declared in the original  "try" block were not accessible outside of the block; 

-  The fragment  at lines 206-207 was reformatted to avoid further error messages: 

       > throw new Exception("AES in CBC mode recovered text is " +  "different from cleartext");
       > System.out.println("AES in CBC mode recovered text is " +  "same as cleartext");



*/

/*
 * Copyright (c) 1997, 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class FourPartyDiffieHellman {

    public static void main(String argv[]) throws Exception {
        // Alice creates her own DH key pair with a 2048-bit key size
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // This DH parameters can also be constructed by creating a
        // DHParameterSpec object using agreed-upon values
        DHParameterSpec dhParamShared = ((DHPublicKey) aliceKpair.getPublic()).getParams();

        // Bob creates his own DH key pair using the same params
        System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamShared);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // Carol creates her own DH key pair using the same params
        System.out.println("CAROL: Generate DH keypair ...");
        KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
        carolKpairGen.initialize(dhParamShared);
        KeyPair carolKpair = carolKpairGen.generateKeyPair();

        // Dave creates his own DH key pair using the same params
        System.out.println("DAVE: Generate DH keypair ...");
        KeyPairGenerator daveKpairGen = KeyPairGenerator.getInstance("DH");
        daveKpairGen.initialize(dhParamShared);
        KeyPair daveKpair = daveKpairGen.generateKeyPair();

        // Alice initialize
        System.out.println("ALICE: Initialize ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Bob initialize
        System.out.println("BOB: Initialize ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Carol initialize
        System.out.println("CAROL: Initialize ...");
        KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
        carolKeyAgree.init(carolKpair.getPrivate());

        // Dave initialize
        System.out.println("DAVE: Initialize ...");
        KeyAgreement daveKeyAgree = KeyAgreement.getInstance("DH");
        daveKeyAgree.init(daveKpair.getPrivate());

        //Phase1 Alice shares key to Bob
        Key ab = aliceKeyAgree.doPhase(bobKpair.getPublic(), false);
        
        //Phase1 Bob shares key to Carol
        Key bc = bobKeyAgree.doPhase(carolKpair.getPublic(), false);

        //Phase1 Carol shares key to Dave
        Key cd = carolKeyAgree.doPhase(daveKpair.getPublic(), false);

        //Phase1 Dave shares key to Alice
        Key da = daveKeyAgree.doPhase(aliceKpair.getPublic(), false);
        
        //Phase2 use Alice and Bob shared key and share with Carol
        Key abc = aliceKeyAgree.doPhase(cd, false);

        //Phase2 use Bob and Carol shared key and share with Dave
        Key bcd = bobKeyAgree.doPhase(da, false);

        //Phase2 use Carol and Dave shared key and share with Alice
        Key cda = carolKeyAgree.doPhase(ab, false);

        //Phase2 use Dave and Alice shared key and share with Bob
        Key dab = daveKeyAgree.doPhase(bc, false);

        
        //Final Phase
        aliceKeyAgree.doPhase(dab, true);
        bobKeyAgree.doPhase(abc, true);
        carolKeyAgree.doPhase(bcd, true);
        daveKeyAgree.doPhase(cda, true);

        // Alice, Bob, and Carol compute their secrets
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        System.out.println("Alice secret: " + toHexString(aliceSharedSecret));

        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        System.out.println("Bob secret: " + toHexString(bobSharedSecret));

        byte[] carolSharedSecret = carolKeyAgree.generateSecret();
        System.out.println("Carol secret: " + toHexString(carolSharedSecret));

        byte[] daveSharedSecret = daveKeyAgree.generateSecret();
        System.out.println("Dave secret: " + toHexString(daveSharedSecret));


        // Compare Alice and Bob
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            throw new Exception("Alice and Bob differ");
        System.out.println("Alice and Bob are the same");

        // Compare Bob and Carol
        if (!java.util.Arrays.equals(bobSharedSecret, carolSharedSecret))
            throw new Exception("Bob and Carol differ");
        System.out.println("Bob and Carol are the same");

        // Compare Carol and Dave
        if (!java.util.Arrays.equals(carolSharedSecret, daveSharedSecret))
            throw new Exception("Carol and Dave differ");
        System.out.println("Carol and Dave are the same");
    }

    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len - 1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
