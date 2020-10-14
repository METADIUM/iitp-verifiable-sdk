# IITP-Verifiable-SDK

## Get it
### Maven
Add the JitPack repository to build file

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

Add dependency

```xml
<dependency>
    <groupId>com.github.METADIUM</groupId>
    <artifactId>iitp-verifiable-sdk</artifactId>
    <version>0.1.5</version>
</dependency>

<dependency>
    <groupId>com.github.METADIUM</groupId>
    <artifactId>did-sdk-java</artifactId>
    <version>0.1.3</version>
</dependency>
```
### Gradle
Add root build.gradle

```gradle
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```
Add dependency

```gradle
dependencies {
    implementation 'com.github.METADIUM:iitp-verifiable-sdk:0.1.5'
    implementation 'com.github.METADIUM:did-sdk-java:0.1.3'
}
```


## Use it

### Metaidum DID 생성

[did-sdk-java](https://github.com/METADIUM/did-sdk-java) 을 참조하기 바랍니다.  


```java
// Create DID
MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://testdelegator.metadium.com"); // set delegator, node url
MetadiumWallet wallet = MetadiumWallet.createDid(delegator);
```



### VC / VP 발급

#### META
```java
MetadiumWallet issuerWallet;
MetadiumWallet userWallet; 

// 만료일
Calendar calendar = Calendar.getInstance();
calendar.add(Calendar.YEAR, 2);

// VC 발급 - Issuer 가 발급
VerifiableCredential vc = new VerifiableCredential();
vc.setTypes(Arrays.asList("CREDENTIAL", "IdentificationCredential"));
vc.setExpirationDate(calendar.getTime());
vc.setIssuanceDate(new Date());
Map<String, Object> subject = new HashMap<>();
subject.put("id", issuerWallet.getDid());	// 소유자 DID. 반드시 넣어야 함
subject.put("name", "Gil-dong Hong");
subject.put("birth_date", "1988-07-21");
subject.put("address", "218 Gajeong-ro, Yuseong-gu, Daejeon, 34129, KOREA");
vc.setCredentialSubject(subject);
String signedVc = new MetadiumSigner(issuerWallet.getDid(), issuerWallet.getKid(), issuerWallet.getKey().getECPrivateKey()).sign(vc); // issuer 의 DID 로 서명

// VP 생성 - 사용자가 VP 생성
VerifiablePresentation vp = new VerifiablePresentation();
vp.setTypes(Arrays.asList("PRESENTATION", "MyPresentation"));
vp.addVerifiableCredential(signedVc);
String signedVp = new MetadiumSigner(userWallet.getDid(), userWallet.getKid(), userWallet.getKey().getECPrivateKey()).sign(vp); // 사용자의 DID 로 서명
```

#### ICON

해당 SDK 로 ICON 키로 서명

```java
Document didDocument;    // Icon SDK 에서 생성한 Did 의 Document
DidKeyHolder keyHolder;  // Icon SDK 에서 생성한 Did 의 DidKeyHolder

// VC 생성은 META 와 동일

// VC 서명
String signedVcByIcon = new MetadiumSigner(document.getId(), keyHolder.getKid(), (ECPrivateKey)keyHolder.getPrivateKey()).sign(vc);

// VP 생성은 META 와 동일

// VP 서명
String signedVcByIcon = new MetadiumSigner(document.getId(), keyHolder.getKid(), (ECPrivateKey)keyHolder.getPrivateKey()).sign(vp);

```

#### INDY

INDY SDK 사용해야 함

### VC / VP 검증

META / ICON 둘 다 검증 가능  
INDY 는 INDY SDK 사용해야 함

```java
// 한번만 미리 설정
VerifiableVerifier.register("did:meta:", MetadiumVerifier.class);	// META
VerifiableVerifier.register("did:icon:", IconVerifier.class);		// ICON
VerifiableVerifier.setResolverUrl("http://129.254.194.103:9000");

String signedVP = ".....";

// VP 검증
VerifiableVerifier verifiableVerifier = new VerifiableVerifier();
VerifiablePresentation resultVp = (VerifiablePresentation)verifiableVerifier.verify(signedVp);

// VC 검증
for (Object vcObject : resultVp.getVerifiableCredentials()) {
	if (vcObject instanceof String) {
		VerifiableCredential resultVc = (VerifiableCredential)verifiableVerifier.verify((String)vcObject);
		
		Map<String, Object> claims = (Map<String, Object>)resultVc.getCredentialSubject();
	}
}
```

### 거래증명 VC 생성 및 검증

현재는 META 만 검증 가능 함

[거래증명 VC 생성/검증 테스트 코드](tree/master/src/test/java/com/iitp/test/ProofTransactionTest.java)

#### 거래 증명 VC 생성

```java
private String makeTxProofVC(MetadiumWallet sellerWallet, String buyerDid, BigInteger price, BigInteger blockNumber, String beforeSignedVC) throws Exception {
	Map<String, String> claims = Stream.of(new String[][] {
		{ "ProductCredential_id", "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000001eee" },	// 테스트로 상품 DID 임의로 고정
		{ "seller_id", sellerWallet.getDid() },
		{ "buyer_id", buyerDid },
		{ "BlockNumber", blockNumber.toString() },
		{ "price", price.toString() },
		{ "sell_date", new SimpleDateFormat("yyyy-MM-dd").format(new Date()) }
	}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
	
	// 이전 거래증명 VC를 claim 에 포함한다.
	if (beforeSignedVC != null) {
		claims.put("OldProductProofCredential", beforeSignedVC);
	}
	
	VerifiableCredential productVC = new VerifiableCredential();
	productVC.setIssuer(URI.create(sellerWallet.getDid()));
	productVC.addTypes(Collections.singletonList("ProductCredential"));
	productVC.setIssuanceDate(new Date());
	productVC.setId(URI.create(UUID.randomUUID().toString()));
	productVC.setCredentialSubject(claims);
	
	// 판매자가 VC 서명
	MetadiumSigner signer = new MetadiumSigner(sellerWallet.getDid(), sellerWallet.getKid(), sellerWallet.getKey().getECPrivateKey());
	return signer.sign(productVC);
}

MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://api.metadium.com/dev");
// 판매자 DID 생성
MetadiumWallet sellerWallet = MetadiumWallet.createDid(delegator);

// 구매자 DID 생성
MetadiumWallet buyerWallet = MetadiumWallet.createDid(delegator);

// 거래_1 에 대한 판매자가 거래증명 VC 생성
String signedProductVC1 = makeTxProofVC(sellerWallet, buyerWallet.getDid(), BigInteger.valueOf(16000), delegator.currentBlockNumber(), null);

// 거래_2 에 대한 판매자가 거래증명 VC 생성
MetadiumWallet buyer2Wallet = MetadiumWallet.createDid(delegator);
String signedProductVC2 = makeTxProofVC(buyerWallet, buyer2Wallet.getDid(), BigInteger.valueOf(20000), delegator.currentBlockNumber(), signedProductVC1);

// 거래_3 에 대한 판매자가 거래증명 VC 생성
MetadiumWallet buyer3Wallet = MetadiumWallet.createDid(delegator);
String signedProductVC3 = makeTxProofVC(buyer2Wallet, buyer3Wallet.getDid(), BigInteger.valueOf(30000), delegator.currentBlockNumber(), signedProductVC2);
```

#### 거래 증명 VC 검증

```java
VerifiableCredential verifyTxProofVC(MetaDelegator delegator, String signedVc) throws Exception {
	MetadiumVerifier verifier = new MetadiumVerifier();
	
	// VC 에서 blockNumber, issuer 를 먼저 가져온다.
	VerifiableCredential vc = verifier.toCredential(SignedJWT.parse(signedVc).getJWTClaimsSet());
	BigInteger blockNumber = new BigInteger(((Map<String, String>)vc.getCredentialSubject()).get("BlockNumber"));
	String issuerDid = vc.getIssuer().toString();
	
	// VC 생성할 당시의 public key 를 얻는다.
	BigInteger publicKey = delegator.getPublicKey(issuerDid, blockNumber);
	verifier.setPublicKey(com.iitp.verifiable.util.ECKeyUtils.toECPublicKey(publicKey, "secp256k1"));
	
	// VC 를 검증한다.
	return (VerifiableCredential)verifier.verify(signedVc, null);
}

// 거래증명VC 와 이전 모든 거래증명VC 를 검증한다.
String txProofVC = "...";
do {
	VerifiableCredential vc = verifyTxProofVC(delegator, vcToVerify);
	
	assertTrue(vc != null);
	
	vcToVerify = ((Map<String, String>)vc.getCredentialSubject()).get("OldProductProofCredential");
} while (vcToVerify != null);
```

### 서명 및 검증 (로그인)

challenge 는 서버에서 SSI 앱으로 전달했다는 가정하에 SSI 앱에서 서명하고 검증 서버가 확인 하는 예제 코드

#### META

```java
// DID 생성
MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://testdelegator.metadium.com");
MetadiumWallet wallet = MetadiumWallet.createDid(delegator);

// META DID 로 SSI 앱에서 서명.
byte[] challenge = "test_message".getBytes(StandardCharset.UTF_8);
Sign.SignatureData signatureData = wallet.getKey().sign(challenge);
ByteBuffer buffer = ByteBuffer.allocate(65);
buffer.put(signatureData.getR());
buffer.put(signatureData.getS());
buffer.put(signatureData.getV());
String signature = Numeric.toHexString(buffer.array());  // 서명값
String did = wallet.getDid();

// signature, did 를 검증해야 할 서버에 전달

// 전달 받은 did, signature 와 미리 알고 있는 challenge 값으로 서버에서 서명 검증
if (wallet.getDid().startsWith("did:meta:")) {
	DidDocument document = DIDResolverAPI.getInstance().getDocument(did);
	if (document.hasRecoverAddressFromSignature(challenge, signature)) {
		// 검증 성공
	}
}
```


