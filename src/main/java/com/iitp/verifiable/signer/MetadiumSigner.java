package com.iitp.verifiable.signer;

import java.io.IOException;
import java.net.URI;
import java.security.interfaces.ECPrivateKey;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iitp.verifiable.Verifiable;
import com.iitp.verifiable.VerifiableCredential;
import com.iitp.verifiable.VerifiablePresentation;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class MetadiumSigner implements VerifiableSigner {
	private static final String JSONLD_KEY_CREDENTIAL_SUBJECT_ID = "id";
	private static final String JWT_HEADER_NONCE = "nonce";

	private String did;
	private String kid;
	private ECPrivateKey privateKey;

	public MetadiumSigner(String did, String kid, ECPrivateKey privateKey) {
		this.did = did;
		this.kid = kid;
		this.privateKey = privateKey;
	}

	@Override
	public String sign(Verifiable verifiable) throws Exception {
		JWTClaimsSet claimsSet;
		if (verifiable instanceof VerifiableCredential) {
			claimsSet = toClaimsSet((VerifiableCredential) verifiable);
		} else {
			claimsSet = toClaimsSet((VerifiablePresentation) verifiable);
		}

		SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256K).keyID(kid).build(), claimsSet);
		ECDSASigner signer = new ECDSASigner(privateKey);
		signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		signedJWT.sign(signer);

		return signedJWT.serialize();
	}

	private JWTClaimsSet toClaimsSet(VerifiablePresentation vp) {
		vp.setHolder(URI.create(did));
		
		LinkedHashMap<String, Object> vpObject = deepCopy(vp.getJsonObject());

		// From verifiable credential, extract parameters in JWT header
		URI jti = vp.getId();
		URI holder = vp.getHolder();

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		if (jti != null) {
			// move id to jwt.jti
			builder.jwtID(jti.toString());
			vpObject.remove(Verifiable.JSONLD_KEY_ID);
		}
		if (holder != null) {
			builder.issuer(holder.toString());
			vpObject.remove(VerifiablePresentation.JSONLD_KEY_HOLDER);
		}
		builder.claim(JWT_HEADER_NONCE, UUID.randomUUID().toString());
		builder.claim("vp", vpObject);

		return builder.build();
	}

	@SuppressWarnings("unchecked")
	private JWTClaimsSet toClaimsSet(VerifiableCredential vc) {
		vc.setIssuer(URI.create(did));

		LinkedHashMap<String, Object> vcObject = deepCopy(vc.getJsonObject());

		// From verifiable credential, extract parameters in JWT header
		URI jti = vc.getId();
		Date expireDate = vc.getExpriationDate();
		URI issuer = vc.getIssuer();
		Date issuedDate = vc.getIssunaceDate();
		Object credentialSubject = vc.getCredentialSubject();
		URI subject = null;
		if (credentialSubject instanceof Map) {
			String id = (String) ((Map<String, Object>) credentialSubject).get(JSONLD_KEY_CREDENTIAL_SUBJECT_ID);
			if (id != null) {
				subject = URI.create(id);
				// remove id of credential subject
				((Map<String, Object>) vcObject.get(VerifiableCredential.JSONLD_KEY_CREDENTIAL_SUBJECT))
						.remove(JSONLD_KEY_CREDENTIAL_SUBJECT_ID);
			}
		}

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		if (jti != null) {
			// move id to jwt.jti
			builder.jwtID(jti.toString());
			vcObject.remove(Verifiable.JSONLD_KEY_ID);
		}
		if (expireDate != null) {
			// move expire date to jwt.exp
			builder.expirationTime(expireDate);
			vcObject.remove(VerifiableCredential.JSONLD_KEY_EXPIRATION_DATE);
		}
		if (issuer != null) {
			// move issuer to jwt.iss
			builder.issuer(issuer.toString());
			
			vcObject.remove(VerifiableCredential.JSONLD_KEY_ISSUSER);
			Map<String, Object> issuerObject = vc.getIssuerObject();
			if (issuerObject != null) {
				vcObject.put(VerifiableCredential.JSONLD_KEY_ISSUSER, issuerObject);
			}
		}
		if (issuedDate != null) {
			// move issue time to jwt.nbf
			builder.issueTime(issuedDate);
			vcObject.remove(VerifiableCredential.JSONLD_KEY_ISSUANCE_DATE);
		}
		if (subject != null) {
			// set subject credentialSubject.id
			builder.subject(subject.toString());
		}
		builder.claim(JWT_HEADER_NONCE, UUID.randomUUID().toString());
		builder.claim("vc", vcObject);

		return builder.build();
	}

	/**
	 * Map deep copy
	 * 
	 * @param src
	 * @return
	 */
	private static LinkedHashMap<String, Object> deepCopy(LinkedHashMap<String, Object> src) {
		ObjectMapper objectMapper = new ObjectMapper();

		try {
			byte[] data = objectMapper.writeValueAsBytes(src);
			return objectMapper.readValue(data, new TypeReference<LinkedHashMap<String, Object>>() {
			});
		} catch (IOException e) {
		}
		// not happened
		return null;
	}
}
