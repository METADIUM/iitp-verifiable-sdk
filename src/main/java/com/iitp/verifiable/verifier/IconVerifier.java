package com.iitp.verifiable.verifier;

import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.iitp.icon.DIDDocVo;
import com.iitp.icon.DidDocumentVo;
import com.iitp.icon.PublicKeyVo;
import com.iitp.verifiable.Verifiable;
import com.iitp.verifiable.util.ECKeyUtils;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class IconVerifier extends Verifier {
	public static final String JSONLD_KEY_CREDENTIAL_SUBJECT_ID = "id";

	private ECPublicKey publicKey = null;
	
	public IconVerifier() {
	}
	
	public IconVerifier(ECPublicKey publicKey) {
		this();
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
				DIDDocVo response = new Gson().fromJson(didDocumentJson, DIDDocVo.class);
				DidDocumentVo didDocument = response.getDidDocument();
                List<PublicKeyVo> publicKeyVoList = didDocument.getPublicKey();
                String kid = signedJWT.getHeader().getKeyID();
                String keyId = kid.substring(kid.lastIndexOf('#')+1);
                for (PublicKeyVo key : publicKeyVoList) {
                    if (key.getId().equals(keyId)) {
                        byte[] publicKeyDecode = Base64.getDecoder().decode(key.getPublicKeyBase64());
                        ecPublicKey = ECKeyUtils.toECPublicKey(publicKeyDecode, "secp256k1");

                        break;
                    }
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
			if (claims.getClaim("claim") != null) {
				return toCredential(claims);
			}
			else if (claims.getClaim("credential") != null) {
				return toPresentation(claims);
			}
		}
		
		return null;
	}
}