package org.mule.extension.DPoP.internal;

import static org.mule.runtime.extension.api.annotation.param.MediaType.ANY;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.commons.io.IOUtils;
import org.mule.runtime.extension.api.annotation.Alias;
import org.mule.runtime.extension.api.annotation.param.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.mule.runtime.extension.api.annotation.param.MediaType.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.util.Base64URL;
import org.mule.runtime.extension.api.annotation.param.Content;
import org.mule.runtime.extension.api.annotation.param.Config;

public class DPoPOperations {

	private static final Logger LOGGER = LoggerFactory.getLogger(DPoPOperations.class);
	
	@MediaType(value = APPLICATION_JSON,strict = false)
	@Alias("DpopToken")
	 public String dpopToken(@Config DPoPConfiguration c,@Content(primary = true) Map<String, Object> payload,@Content String url,@Content String method) {
		String dpopToken;
		LOGGER.debug("DPoP Token Method started");
		dpopToken = requestBodyPayloadGenerateDPoP(c.getPrivateKey(), c.getPublicKey(), url,method,c,payload);
		String token = simplify("{\n" + "token" + ":" + dpopToken + "\n}");
		if(token != null) LOGGER.debug("DPoP Token generated successfully");
		
		else LOGGER.debug("DPoP cannot be null.Invalid");
		return token;
		
	 }
	
	@MediaType(value = APPLICATION_JSON,strict = false)
	private static String requestBodyPayloadGenerateDPoP(String privateKey, String publicKey, String url, String httpMethod,@Config DPoPConfiguration c,Map<String, Object> payload) {
        String dpopToken = null;
        try {

            FileInputStream fis = new FileInputStream(c.getFilePath());
            String requestBody = IOUtils.toString(fis, "UTF-8");
            requestBody = simplify(requestBody);

            List<String> requestHeaderKeyLists = new LinkedList<>(payload.keySet());
            String requestHeaderHashs = createSHAHash(convertMapToString(payload));
            String requestBodyHashs = createSHAHash(requestBody);

            dpopToken = generateDPoP(privateKey, publicKey, url, httpMethod, requestBodyHashs, requestHeaderKeyLists, requestHeaderHashs,
                    null, null, null, null);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return dpopToken;
    }
	
	@MediaType(value=ANY,strict = false)
	private static String convertMapToString(Map<String, ?> map) {
        String mapAsString = map.keySet().stream()
                .map(key -> key + "=" + map.get(key))
                .collect(Collectors.joining(", ", "{", "}"));
        return mapAsString;
    }


    // using auth0 generate dpop
	@MediaType(value=ANY,strict = false)
    private static String generateDPoP(String privateKey, String publicKey, String url,
                                      String httpMethods, String requestBodyHashs, List<String> requestHeaderKeyLists,
                                      String requestHeaderHashs, List<String> selectivePayloadKeyLists, String selectivePayloadHashs,
                                      List<String> formParamKeyLists, String  formParamHashs) {

        String dpopToken = null;
        try {

            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider()
            );

            RSAPrivateKey rsaPrivateKey;
            privateKey = privateKey.replace("\n", "");
            privateKey = privateKey.replace("-----BEGIN PRIVATE KEY-----", "");
            privateKey = privateKey.replace("-----END PRIVATE KEY-----", "");

            byte[] decodedPv = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpecPv = new PKCS8EncodedKeySpec(decodedPv);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(keySpecPv);

            RSAPublicKey rsaPublicKey;
            publicKey = publicKey.replace("\n", "");
            publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "");
            publicKey = publicKey.replace("-----END PUBLIC KEY-----", "");

            byte[] data = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            rsaPublicKey = (RSAPublicKey) kf.generatePublic(spec);


            Algorithm algorithm = Algorithm.RSA256(null, rsaPrivateKey);

            Map<String, Object> headerClaim = new HashMap<>();
            headerClaim.put("typ", "dpop+jwt");
            headerClaim.put("jwk", generateJWK(rsaPublicKey));

            JWTCreator.Builder builder = JWT.create();

            builder.withJWTId(UUID.randomUUID().toString())
                    .withHeader(headerClaim)
                    .withIssuedAt(new Date(System.currentTimeMillis()))
                    .withClaim("htm", httpMethods)
                    .withClaim("htu", url);

            if (requestBodyHashs != null)
                builder.withClaim("requestBodyHashs", requestBodyHashs);
            else if (selectivePayloadHashs != null && selectivePayloadKeyLists != null) {
                builder.withClaim("selectivePayloadHash", selectivePayloadHashs);
                builder.withClaim("selectivePayloadKeyLists", selectivePayloadKeyLists);
            } else if ( formParamHashs != null && formParamKeyLists != null) {
                builder.withClaim(" formParamHashs",  formParamHashs);
                builder.withClaim("formParamKeyLists", formParamKeyLists);
            }

            if (requestHeaderHashs != null && requestHeaderKeyLists != null) {
                builder.withClaim("requestHeaderKeyLists", requestHeaderKeyLists);
                builder.withClaim("requestHeaderHash", requestHeaderHashs);
            }

            dpopToken = builder.sign(algorithm);

            return dpopToken;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return dpopToken;
    }
   
	@MediaType(value=ANY)
    private static Map<String, String> generateJWK(RSAPublicKey rsa) {
        Map<String, String> values = new HashMap<>();
        values.put("kty", rsa.getAlgorithm());
        values.put("e", Base64.getUrlEncoder().encodeToString(rsa.getPublicExponent().toByteArray()));
        values.put("kid", UUID.randomUUID().toString());
        values.put("n", String.valueOf(Base64URL.encode(rsa.getModulus())));
        return values;
    }
    
    private static String createSHAHash(String input) throws NoSuchAlgorithmException {

        String hashtext = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageDigest =
                md.digest(input.getBytes(StandardCharsets.UTF_8));

        hashtext = convertToHex(messageDigest);
        return hashtext;
    }

    private static String convertToHex(final byte[] messageDigest) {
        BigInteger bigint = new BigInteger(1, messageDigest);
        String hexText = bigint.toString(16);
        while (hexText.length() < 32) {
            hexText = "0".concat(hexText);
        }
        return hexText;
    }
    
    @MediaType(value=APPLICATION_JSON)
    private static String simplify(String json) {
        Gson gson = new GsonBuilder().create();
        JsonElement el = JsonParser.parseString(json);
        return gson.toJson(el);
    }

	 
}
