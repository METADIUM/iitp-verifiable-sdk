package com.iitp.test;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import com.iitp.verifiable.VerifiableCredential;
import com.iitp.verifiable.VerifiablePresentation;
import com.iitp.verifiable.VerifiableVerifier;
import com.iitp.verifiable.signer.MetadiumSigner;
import com.iitp.verifiable.util.ECKeyUtils;
import com.iitp.verifiable.verifier.IconVerifier;
import com.iitp.verifiable.verifier.MetadiumVerifier;



public class MetaVerifiableTest {
    private static final String ISSUER_DID = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382";
    private static final String ISSUER_KID = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382#MetaManagementKey#59ddc27f5bc6983458eac013b1e771d11c908683";
    private static final BigInteger ISSUER_PRIVATE_KEY_BIG_INT = new BigInteger("fdcdca38d0c62f3564f90afdc4c04c1f936b9edf95b5d8841a70b40cc84cfd90", 16);
    private static final ECPrivateKey ISSUER_PRIVATE_KEY = ECKeyUtils.toECPrivateKey(ISSUER_PRIVATE_KEY_BIG_INT, "secp256k1");
    private static final ECPublicKey ISSUER_PUBLIC_KEY = ECKeyUtils.toECPublicKey(DatatypeConverter.parseHexBinary("04e318e1bcba505204708dde69e75ec2c312b5b5334249a3631f49c381d6389efc24b1db98dba1573f404da2ef3b5d65894b065d31d23be70d2d2fad15d5166f69"), "secp256k1");
    
    
    private static final String USER_DID = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b";
    private static final String USER_KID = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511";
    private static final BigInteger USER_PRIVATE_KEY_BIG_INT = new BigInteger("86975dca6a36062768cf4b648b5b3f712caa2d1d61fa42520624a8e574788822", 16);
    private static final ECPrivateKey USER_PRIVATE_KEY = ECKeyUtils.toECPrivateKey(USER_PRIVATE_KEY_BIG_INT, "secp256k1");
    private static final ECPublicKey USER_PUBLIC_KEY = ECKeyUtils.toECPublicKey(DatatypeConverter.parseHexBinary("04d3e33a1791e77362130f9c11352933ea035e6fa3079610aa60ba800c9b963e132ed8db542d305027c4f1738efbed15bc63dc9f619c74c8e68287576769f5da3e"), "secp256k1");

    private String createVC() throws Exception {
    	Calendar calendar = Calendar.getInstance();
    	calendar.add(Calendar.YEAR, 2);
    	
    	// make VC
    	VerifiableCredential vc = new VerifiableCredential();
    	vc.setTypes(Arrays.asList("CREDENTIAL", "IdentificationCredential"));
    	vc.setExpirationDate(calendar.getTime());
    	vc.setIssuanceDate(new Date());
    	Map<String, Object> subject = new HashMap<>();
    	subject.put("id", USER_DID);	// 소유자 DID. 반드시 넣어야 함
    	subject.put("name", "Gil-dong Hong");
    	subject.put("birth_date", "1988-07-21");
    	subject.put("address", "218 Gajeong-ro, Yuseong-gu, Daejeon, 34129, KOREA");
    	vc.setCredentialSubject(subject);
    	System.out.println("VC = "+vc.toJSONString());
    	
    	// sign vc
    	MetadiumSigner signer = new MetadiumSigner(ISSUER_DID, ISSUER_KID, ISSUER_PRIVATE_KEY);
    	String signedVc = signer.sign(vc);
    	System.out.println("Signed VC = "+signedVc);
    	
    	return signedVc;

    }
    
	
    @Test
    public void issuedVP() throws Exception {
    	// issued VC
    	String vc = createVC();
    	
    	// issued VP
    	VerifiablePresentation vp = new VerifiablePresentation();
    	vp.setTypes(Arrays.asList("PRESENTATION", "MyPresentation"));
    	vp.addVerifiableCredential(vc);
    	System.out.println("VP = "+vp.toJSONString());
    	
    	MetadiumSigner signer = new MetadiumSigner(USER_DID, USER_KID, USER_PRIVATE_KEY);
    	String signedVp = signer.sign(vp);
    	System.out.println("Signed VP = "+signedVp);
    	
    	// verify VP
    	MetadiumVerifier verifier = new MetadiumVerifier(USER_PUBLIC_KEY);
    	VerifiablePresentation resultVp = (VerifiablePresentation)verifier.verify(signedVp, null);
    	System.out.println("result VP = "+resultVp.toJSONString());
    	
    	for (Object o : resultVp.getVerifiableCredentials()) {
    		if (o instanceof String) {
    	    	MetadiumVerifier verifier2 = new MetadiumVerifier(ISSUER_PUBLIC_KEY);
    	    	VerifiableCredential resultVc = (VerifiableCredential)verifier2.verify((String)o, null);
    	    	
    	    	System.out.println("result VC = "+resultVc.toJSONString());
    		}
    	}
    }
    
    @Test
    public void realTest() throws Exception {
    	// issued VC / VP with META
    	String vc = createVC();
    	VerifiablePresentation vp = new VerifiablePresentation();
    	vp.setTypes(Arrays.asList("PRESENTATION", "MyPresentation"));
    	vp.addVerifiableCredential(vc);
    	System.out.println("VP = "+vp.toJSONString());
    	MetadiumSigner signer = new MetadiumSigner(USER_DID, USER_KID, USER_PRIVATE_KEY);
    	String signedVp = signer.sign(vp);
    	System.out.println("Signed VP = "+signedVp);
    	
    	// preset
    	VerifiableVerifier.register("did:meta:", MetadiumVerifier.class);	// META
    	VerifiableVerifier.register("did:icon:", IconVerifier.class);		// ICON
    	VerifiableVerifier.setResolverUrl("https://testnetresolver.metadium.com"); // Set universal resolver (http://129.254.194.103:9000). 테스트로 META resolver
    	
    	// verify VP
    	VerifiableVerifier verifiableVerifier = new VerifiableVerifier();
		VerifiablePresentation resultVp = (VerifiablePresentation)verifiableVerifier.verify(signedVp);
		
		// verify VC
    	for (Object vcObject : resultVp.getVerifiableCredentials()) {
    		if (vcObject instanceof String) {
    			VerifiableCredential resultVc = (VerifiableCredential)verifiableVerifier.verify((String)vcObject);
    			
    			System.out.println("claims = "+resultVc.getCredentialSubject().toString());
    		}
    	}
    }
}
