package com.iitp.verifiable;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iitp.verifiable.verifier.Verifier;
import com.nimbusds.jwt.SignedJWT;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class VerifiableVerifier {
	private static String resolverUrl;
	private static Map<String, Class<? extends Verifier>> signerMap = new HashMap<>();
	
	public static void register(String didPrefix, Class<? extends Verifier> verifier) {
		signerMap.put(didPrefix, verifier);
	}
	
	public static void setResolverUrl(String url) {
		resolverUrl = url;
	}
	
	public Verifiable verify(String verifableJson) throws Exception {
		// check resolver url
		if (resolverUrl == null) {
			throw new IllegalStateException("Not set resolver url. VerifiableVerifier.setUrl()");
		}
		
		// check did
		String issuerDid = null;
		try {
			SignedJWT signedJWT = SignedJWT.parse(verifableJson);
			issuerDid = signedJWT.getJWTClaimsSet().getIssuer();
		} catch (ParseException e) {
			try {
				Map<String, Object> map = new ObjectMapper().readValue(verifableJson, new TypeReference<Map<String, Object>>(){});
				
				if (map.containsKey(VerifiableCredential.JSONLD_KEY_ISSUSER)) {
					issuerDid = (String)map.get(VerifiableCredential.JSONLD_KEY_ISSUSER);
				}
				else if (map.containsKey(VerifiablePresentation.JSONLD_KEY_HOLDER)) {
					issuerDid = (String)map.get(VerifiablePresentation.JSONLD_KEY_HOLDER);
				}
			} catch (JsonProcessingException e1) {
			}
		}
		if (issuerDid == null) {
			throw new IllegalArgumentException("Not found did of issuer");
		}

		// Get verifier
		Verifier verifier = null;
		for (Entry<String, Class<? extends Verifier>> entry : signerMap.entrySet()) {
			if (issuerDid.startsWith(entry.getKey())) {
				try {
					verifier = entry.getValue().newInstance();
				} catch (InstantiationException | IllegalAccessException e) {
					throw new IllegalArgumentException("Fail to create instance of Verifier", e);
				}
			}
		}
		if (verifier == null) {
			throw new IllegalArgumentException("Not found verifier of "+issuerDid);
		}
		
		String didDocumentJson;
		try {
			didDocumentJson = getDidDocument(resolverUrl, issuerDid);
		} catch (IOException e) {
			throw new IOException("Resovler io error", e);
		}
		
		if (didDocumentJson == null) {
			throw new IllegalArgumentException("Not found did of issuer in resolver. "+issuerDid);
		}
		
		try {
			return verifier.verify(verifableJson, didDocumentJson);
		} catch (Exception e) {
			throw e;
		}
	}
	
	
    private String getDidDocument(String url, String did) throws IOException {
    	Request request = new Request.Builder()
    			.url(url+"/1.0/identifiers/"+did)
    			.build();
    	
        OkHttpClient okHttpClient = new OkHttpClient.Builder().build();
		Response response = okHttpClient.newCall(request).execute();
		
		if (response.isSuccessful()) {
			return response.body().string();
		}
		else {
			return null;
		}

    }

}
