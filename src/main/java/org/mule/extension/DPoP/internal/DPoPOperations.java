package org.mule.extension.DPoP.internal;

import static org.mule.runtime.extension.api.annotation.param.MediaType.ANY;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import org.apache.commons.io.IOUtils;
import org.mule.runtime.extension.api.annotation.Alias;
import org.mule.runtime.extension.api.annotation.error.Throws;
import org.mule.runtime.extension.api.annotation.param.MediaType;
import org.mule.runtime.extension.api.annotation.param.ParameterGroup;
import org.mule.runtime.extension.api.exception.ModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import static org.mule.runtime.extension.api.annotation.param.MediaType.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.util.Base64URL;


import org.mule.runtime.extension.api.annotation.param.Config;

public class DPoPOperations {


	private static final Logger LOGGER = LoggerFactory.getLogger(DPoPOperations.class);

	@Alias("dpopify")
	@MediaType(value = APPLICATION_JSON)
	@Throws(DPoPErrorProvider.class)
	public String dpopToken(@ParameterGroup(name = "DPoP Setting") DPoPParameter p, @Config DPoPConfiguration c)  
			throws IOException {
		String dpopToken, access_Token, DPoP;
		LOGGER.debug("DPoP Token Method started");

		access_Token = accessToken(c.getPrivateKey(), c.getPublicKey(), c.getAccessTokenUrl(), c.getUsername(), c.getPassword());
		dpopToken = noPayloadGenerateDPoP(c.getPrivateKey(), c.getPublicKey(), p.getUrl(), p.getPriority());
		DPoP = simplify("{\n" + "DPoP" + ":" + dpopToken + "\n}");

		if (DPoP != null)
			LOGGER.debug("DPoP Token generated successfully");
		else
			LOGGER.debug("DPoP cannot be null.Invalid");
		return simplify("[\n" + DPoP + "," + "\n" + access_Token + "\n]");

	}

	@MediaType(value = ANY, strict = false)
	private static String noPayloadGenerateDPoP(String privateKey, String publicKey, String url, String httpMethod) {
		String dpopToken;
		dpopToken = generateDPoP(privateKey, publicKey, url, httpMethod, null, null, null, null, null, null, null);

		return dpopToken;
	}

	@MediaType(value = ANY, strict = false)
	private static String convertMapToString(Map<String, ?> map) {
		String mapAsString = map.keySet().stream().map(key -> key + "=" + map.get(key))
				.collect(Collectors.joining(", ", "{", "}"));
		return mapAsString;
	}

	// using auth0 generate dpop
	@MediaType(value = ANY, strict = false)
	private static String generateDPoP(String privateKey, String publicKey, String url, String httpMethods,
			String requestBodyHashs, List<String> requestHeaderKeyLists, String requestHeaderHashs,
			List<String> selectivePayloadKeyLists, String selectivePayloadHashs, List<String> formParamKeyLists,
			String formParamHashs) {

		String dpopToken = null;
		try {

			java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			RSAPrivateKey rsaPrivateKey;
			privateKey = privateKey.replace("-----BEGIN PRIVATE KEY-----", "");
			privateKey = privateKey.replace("-----END PRIVATE KEY-----", "");
			privateKey = privateKey.replace("\n", "");
			privateKey = privateKey.replace("\r", "");

			byte[] decodedPv = Base64.getDecoder().decode(privateKey);
			PKCS8EncodedKeySpec keySpecPv = new PKCS8EncodedKeySpec(decodedPv);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(keySpecPv);

			RSAPublicKey rsaPublicKey;
			publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "");
			publicKey = publicKey.replace("-----END PUBLIC KEY-----", "");
			publicKey = publicKey.replace("\n", "");
			publicKey = publicKey.replace("\r", "");

			byte[] data = Base64.getDecoder().decode(publicKey);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
			rsaPublicKey = (RSAPublicKey) kf.generatePublic(spec);

			Algorithm algorithm = Algorithm.RSA256(null, rsaPrivateKey);

			Map<String, Object> headerClaim = new HashMap<>();
			headerClaim.put("typ", "dpop+jwt");
			headerClaim.put("jwk", generateJWK(rsaPublicKey));

			JWTCreator.Builder builder = JWT.create();

			builder.withJWTId(UUID.randomUUID().toString()).withHeader(headerClaim)
					.withIssuedAt(new Date(System.currentTimeMillis())).withClaim("htm", httpMethods)
					.withClaim("htu", url);

			if (requestBodyHashs != null)
				builder.withClaim("requestBodyHashs", requestBodyHashs);
			else if (selectivePayloadHashs != null && selectivePayloadKeyLists != null) {
				builder.withClaim("selectivePayloadHash", selectivePayloadHashs);
				builder.withClaim("selectivePayloadKeyLists", selectivePayloadKeyLists);
			} else if (formParamHashs != null && formParamKeyLists != null) {
				builder.withClaim(" formParamHashs", formParamHashs);
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

	@MediaType(value = ANY)
	private static Map<String, String> generateJWK(RSAPublicKey rsa) {
		Map<String, String> values = new HashMap<>();
		values.put("kty", rsa.getAlgorithm());
		values.put("e", Base64.getUrlEncoder().encodeToString(rsa.getPublicExponent().toByteArray()));
		values.put("kid", UUID.randomUUID().toString());
		values.put("n", String.valueOf(Base64URL.encode(rsa.getModulus())));
		return values;
	}

	@MediaType(value = APPLICATION_JSON)
	private static String simplify(String json) {
		Gson gson = new GsonBuilder().create();
		JsonElement el = JsonParser.parseString(json);
		return gson.toJson(el);
	}

	/* Method for calling Token url */
	@MediaType(value = APPLICATION_JSON)
	private String accessToken(String privateKey, String publicKey, String accessTokenUrl, String username,
			String password) throws IOException {
		String payload = "grant_type=client_credentials";
		String response = null;
		int status=200;
		String userCredentials = username + ":" + password;
		HttpsURLConnection https;
		String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userCredentials.getBytes()));
		URL url = new URL(accessTokenUrl);
		URLConnection con = url.openConnection();
		con.setDoOutput(true);
		con.addRequestProperty("User-Agent", "Mozilla");
		https = (HttpsURLConnection) con;
		https.setRequestMethod("POST");
		https.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		https.setRequestProperty("Authorization", basicAuth);
		https.setRequestProperty("DPoP", noPayloadGenerateDPoP(privateKey, publicKey, accessTokenUrl, "POST"));
		byte[] postData = payload.getBytes("utf-8");
		int postDataLength = postData.length;
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.write(postData, 0, postDataLength);
		status = ((HttpURLConnection) con).getResponseCode();
		response = getHttpResponse(https,status);
		
		return response;
	}

	/* Method for building response */
	@MediaType(value = APPLICATION_JSON)
	private String getHttpResponse(URLConnection con,int status) throws UnsupportedEncodingException, IOException {
		StringBuilder response = null;
		try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "utf-8"))) {
			response = new StringBuilder();
			String responseLine = null;
			while ((responseLine = br.readLine()) != null) {
				response.append(responseLine.trim());
			}
		}
		catch(Exception e) {
			if(status == 404) {
				throw new ModuleException("Requested API resource path does not exist. Please review Fiserv API documentation at 'https://developer.fiserv.com/merchants'.\"",DPoPError.NOT_FOUND);
			}
			else if(status == 403) {
				throw new ModuleException("Invalid DPoP",DPoPError.FORBIDDEN);
			}
			else if(status == 500) {
				throw new ModuleException("Invalid username and password",DPoPError.INTERNAL_SERVER_ERROR);
			}
			else {
				throw new ModuleException("Something went wrong while generating access token", DPoPError.INTERNAL_SERVER_ERROR);
			}
		}
		return response.toString();
	}

}

