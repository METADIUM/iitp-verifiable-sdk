package com.iitp.verifiable;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iitp.verifiable.verifier.Verifier;
import com.nimbusds.jwt.SignedJWT;

import net.jodah.expiringmap.ExpiringMap;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class VerifiableVerifier {
	private static String resolverUrl;
	private static Map<String, Class<? extends Verifier>> signerMap = new HashMap<>();
	
	private static final OkHttpClient okHttpClient = new OkHttpClient.Builder().build();
	
	private static final ExpiringMap<String, String> didDocumentCache = ExpiringMap.builder()
            .variableExpiration()
            .expiration(1, TimeUnit.MINUTES)
            .build();
	
	public static void register(String didPrefix, Class<? extends Verifier> verifier) {
		signerMap.put(didPrefix, verifier);
	}
	
	public static void setResolverUrl(String url) {
		resolverUrl = url;
	}
	
	public static void setDidDocumentCacheTime(long duration, TimeUnit timeUnit) {
		didDocumentCache.setExpiration(duration, timeUnit);
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
    	String didDocumentJson = didDocumentCache.get(did);
    	if (didDocumentJson != null) {
    		System.out.println("cached did document : "+didDocumentJson);
    		return didDocumentJson;
    	}
    	
    	Request request = new Request.Builder()
    			.url(url+"/1.0/identifiers/"+did)
    			.build();
        
		Response response = okHttpClient.newCall(request).execute();
		
		if (response.isSuccessful()) {
			didDocumentJson = response.body().string();
			didDocumentCache.put(did, didDocumentJson);
			return didDocumentJson;
		}
		else {
			return null;
		}

    }

}
