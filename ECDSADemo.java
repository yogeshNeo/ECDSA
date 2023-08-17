package com.transactional;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

/**
 * Hashing and ECDSA signature using cryptographic Algo
 */
public class ECDSADemo {

    private static final String SPEC = "secp256r1";
    private static final String ALGO = "SHA256withECDSA";

    public static void main(String[] args) {
        try {
            ECDSADemo ECDSADemo = new ECDSADemo();
            JSONObject obj = ECDSADemo.sender();
            boolean result = ECDSADemo.receiver(obj);
            System.out.println("Is Signature verified :: " + result);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ECDSADemo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(ECDSADemo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(ECDSADemo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(ECDSADemo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(ECDSADemo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(ECDSADemo.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private JSONObject sender() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        ECGenParameterSpec ecSpec = new ECGenParameterSpec(SPEC);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair keypair = g.generateKeyPair();
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        String plaintext = "Hello";

        Signature ecdsaSign = Signature.getInstance(ALGO);
        System.out.println("private key is :: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ecdsaSign.sign();
        String pub = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String sig = Base64.getEncoder().encodeToString(signature);
        System.out.println("signature is :: " + sig);
        System.out.println("public key is :: " + pub);

        JSONObject obj = new JSONObject();
        obj.put("publicKey", pub);
        obj.put("signature", sig);
        obj.put("message", plaintext);
        obj.put("algorithm", ALGO);

        return obj;
    }

    private boolean receiver(JSONObject obj) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(obj.getString("publicKey")));
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        System.out.println("Receiver publ :: " + obj.getString("publicKey"));

        Signature ecdsaVerify = Signature.getInstance(obj.getString("algorithm"));
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(obj.getString("message").getBytes(StandardCharsets.UTF_8));
        System.out.println("Message is :: " + obj.getString("message"));
        System.out.println("Receiver signature :: " + obj.getString("signature"));
        return ecdsaVerify.verify(Base64.getDecoder().decode(obj.getString("signature")));
    }

}