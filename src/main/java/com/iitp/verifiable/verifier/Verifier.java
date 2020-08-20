package com.iitp.verifiable.verifier;

import java.net.URI;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import com.iitp.verifiable.Verifiable;
import com.iitp.verifiable.VerifiableCredential;
import com.iitp.verifiable.VerifiablePresentation;
import com.nimbusds.jwt.JWTClaimsSet;

public abstract class Verifier {
	private static final String JSONLD_KEY_CREDENTIAL_SUBJECT_ID = "id";

	
	public abstract Verifiable verify(String verifiable, String didDocumentJson) throws Exception;
	
	@SuppressWarnings("unchecked")
	public VerifiableCredential toCredential(JWTClaimsSet claimsSet) {
		String id = claimsSet.getJWTID();
		Date expireDate = claimsSet.getExpirationTime();
		String issuer = claimsSet.getIssuer();
		Date issuedDate = claimsSet.getIssueTime();
		String subject = claimsSet.getSubject();
		Map<String, Object> vcClaim = (Map<String, Object>)claimsSet.getClaim("claim");
		
		VerifiableCredential vc = new VerifiableCredential();
		vc.setTypes((Collection<String>)claimsSet.getClaim("type"));
		if (id != null) {
			vc.setId(URI.create(id));
		}
		if (expireDate != null) {
			vc.setExpirationDate(expireDate);
		}
		if (issuer != null) {
			Object issuerObject = vcClaim.get(VerifiableCredential.JSONLD_KEY_ISSUSER);
			if (issuerObject instanceof Map) {
				vc.setIssuer(URI.create(issuer), (Map<String, Object>)issuerObject);
			}
			else {
				vc.setIssuer(URI.create(issuer));
			}
		}
		if (issuedDate != null) {
			vc.setIssuanceDate(issuedDate);
		}
		vc.setCredentialSubject(vcClaim);
		if (subject != null) {
			Object credentialSubject = vc.getCredentialSubject();
			if (credentialSubject instanceof Map) {
				((Map<String, Object>)credentialSubject).put(JSONLD_KEY_CREDENTIAL_SUBJECT_ID, subject);
			}
		}
		
		return vc;
	}
	
	/**
	 * convert from JWT to Verifiable presentation.
	 * @see <a href="https://w3c.github.io/vc-data-model/#jwt-decoding">JWT Decoding</a>
	 * @param claimsSet JWT
	 * @return verifiable presentation
	 */
	@SuppressWarnings("unchecked")
	public VerifiablePresentation toPresentation(JWTClaimsSet claimsSet) {
		String id = claimsSet.getJWTID();
		String holder = claimsSet.getIssuer();
		
		Collection<Object> vpClaim = (Collection<Object>)claimsSet.getClaim("credential");
		
		VerifiablePresentation vp = new VerifiablePresentation();
		if (id != null) {
			vp.setId(URI.create(id));
		}
		if (holder != null) {
			vp.setHolder(URI.create(holder));
		}
		vp.setTypes((Collection<String>)claimsSet.getClaim("type"));
		for (Object object : vpClaim) {
			vp.addVerifiableCredential(object);
		}
		
		return vp;
	}
}
