package com.iitp.verifiable.verifier;

import java.security.interfaces.ECPublicKey;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.iitp.verifiable.Verifiable;
import com.metaidum.did.resolver.client.DIDResolverResponse;
import com.metaidum.did.resolver.client.document.DidDocument;
import com.metaidum.did.resolver.client.document.PublicKey;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class MetadiumVerifier extends Verifier {

	private ECPublicKey publicKey = null;
	
	public MetadiumVerifier() {
	}
	
	public MetadiumVerifier(ECPublicKey publicKey) {
		this();
		this.publicKey = publicKey;
	}
	
	public void setPublicKey(ECPublicKey publicKey) {
		this.publicKey = publicKey;
	}


	@Override
	public Verifiable verify(String verifiable, String didDocumentJson) throws Exception {
		SignedJWT signedJWT = SignedJWT.parse(verifiable);
		
		ECPublicKey ecPublicKey = null;
		if (publicKey != null) {
			ecPublicKey = publicKey;
		}
		else {
			try {
				DIDResolverResponse response = new Gson().fromJson(didDocumentJson, DIDResolverResponse.class);
				DidDocument didDocument = response.getDidDocument();
				PublicKey publicKey = didDocument.getPublicKey(signedJWT.getHeader().getKeyID());
				if (publicKey != null) {
					ecPublicKey = (ECPublicKey)publicKey.getPublicKey();
				}
				
			}
			catch (JsonSyntaxException e) {
			}
		}
		
		if (ecPublicKey == null) {
			throw new IllegalStateException("Not found public key");
		}
		
		ECDSAVerifier verifier = new ECDSAVerifier(ecPublicKey);
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		
		if (signedJWT.verify(verifier)) {
			JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
			if (claims.getClaim("vc") != null) {
				return toCredential(claims);
			}
			else if (claims.getClaim("vp") != null) {
				return toPresentation(claims);
			}

		}
		
		return null;
	}
}