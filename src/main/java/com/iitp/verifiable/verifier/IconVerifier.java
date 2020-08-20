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
import com.nimbusds.jwt.JWTClaimsSet;

import foundation.icon.did.jwt.Jwt;

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
		Jwt jwt = Jwt.decode(verifiable);
		
		ECPublicKey ecPublicKey = null;
		if (publicKey != null) {
			ecPublicKey = publicKey;
		}
		else {
			try {
				DIDDocVo response = new Gson().fromJson(didDocumentJson, DIDDocVo.class);
				DidDocumentVo didDocument = response.getDidDocument();
                List<PublicKeyVo> publicKeyVoList = didDocument.getPublicKey();
                String kid = jwt.getHeader().getKid();
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
		
		if (jwt.verify(ecPublicKey).isSuccess()) {
			JWTClaimsSet claims = JWTClaimsSet.parse(new Gson().toJson(jwt.getPayload().getMap()));
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