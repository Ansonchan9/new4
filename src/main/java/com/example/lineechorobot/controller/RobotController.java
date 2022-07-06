package com.example.lineechorobot.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.tomcat.util.codec.binary.Base64;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.lineechorobot.handler.MessageHandler;

@RequestMapping("/")
@RestController
public class RobotController {

	@Value("${line.user.secret}")
	private String LINE_SECRET;
	
	@Autowired
	private MessageHandler messageHandler;
	@GetMapping("/")
	public ResponseEntity test() {
		return new ResponseEntity("首頁", HttpStatus.OK);
	}

	@PostMapping("/callback")
	public ResponseEntity messagingAPI(@RequestHeader("X-Line-Signature") String X_Line_Signature,
			@RequestBody String requestBody) throws UnsupportedEncodingException, IOException {
		if (checkFromLine(requestBody, X_Line_Signature)) {
			System.out.println("驗證通過");
			JSONObject object = new JSONObject(requestBody);
			for (int i = 0; i < object.getJSONArray("events").length(); i++) {
				if (object.getJSONArray("events").getJSONObject(i).getString("type").equals("message")) {
					messageHandler.doAction(object.getJSONArray("events").getJSONObject(i));
				}
			}
			return new ResponseEntity<String>("OK", HttpStatus.OK);
		}
		System.out.println("驗證不通過");
		return new ResponseEntity<String>("Not line platform", HttpStatus.BAD_GATEWAY);
	}

	public boolean checkFromLine(String requestBody, String X_Line_Signature) {
		SecretKeySpec key = new SecretKeySpec(LINE_SECRET.getBytes(), "HmacSHA256");
		Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			byte[] source = requestBody.getBytes("UTF-8");
			String signature = Base64.encodeBase64String(mac.doFinal(source));
			if (signature.equals(X_Line_Signature)) {
				return true;
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

	private static String authority;
	private static String clientId;
	private static String secret;
	private static String scope;
	private static ConfidentialClientApplication app;

	public static void main(String args[]) throws Exception{

		setUpSampleData();

		try {
			BuildConfidentialClientObject();
			IAuthenticationResult result = getAccessTokenByClientCredentialGrant();
			String usersListFromGraph = getUsersListFromGraph(result.accessToken());

			System.out.println("Users in the Tenant = " + usersListFromGraph);
			System.out.println("Press any key to exit ...");
			System.in.read();

		} catch(Exception ex){
			System.out.println("Oops! We have an exception of type - " + ex.getClass());
			System.out.println("Exception message - " + ex.getMessage());
			throw ex;
		}
	}
	private static void BuildConfidentialClientObject() throws Exception {

		// Load properties file and set properties used throughout the sample
		app = ConfidentialClientApplication.builder(
						clientId,
						ClientCredentialFactory.createFromSecret(secret))
				.authority(authority)
				.build();
	}

	private static IAuthenticationResult getAccessTokenByClientCredentialGrant() throws Exception {

		// With client credentials flows the scope is ALWAYS of the shape "resource/.default", as the
		// application permissions need to be set statically (in the portal), and then granted by a tenant administrator
		ClientCredentialParameters clientCredentialParam = ClientCredentialParameters.builder(
						Collections.singleton(scope))
				.build();

		CompletableFuture<IAuthenticationResult> future = app.acquireToken(clientCredentialParam);
		return future.get();
	}

	private static String getUsersListFromGraph(String accessToken) throws IOException {
		URL url = new URL("https://graph.microsoft.com/v1.0/users");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();

		conn.setRequestMethod("GET");
		conn.setRequestProperty("Authorization", "Bearer " + accessToken);
		conn.setRequestProperty("Accept","application/json");

		int httpResponseCode = conn.getResponseCode();
		if(httpResponseCode == HTTPResponse.SC_OK) {

			StringBuilder response;
			try(BufferedReader in = new BufferedReader(
					new InputStreamReader(conn.getInputStream()))){

				String inputLine;
				response = new StringBuilder();
				while (( inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
			}
			return response.toString();
		} else {
			return String.format("Connection returned HTTP code: %s with message: %s",
					httpResponseCode, conn.getResponseMessage());
		}
	}

	/**
	 * Helper function unique to this sample setting. In a real application these wouldn't be so hardcoded, for example
	 * different users may need different authority endpoints or scopes
	 */
	private static void setUpSampleData() throws IOException {
		// Load properties file and set properties used throughout the sample
		Properties properties = new Properties();
		properties.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("application.properties"));
		authority = properties.getProperty("AUTHORITY");
		clientId = properties.getProperty("CLIENT_ID");
		secret = properties.getProperty("SECRET");
		scope = properties.getProperty("SCOPE");
	}
}
