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
    <version>0.1.2</version>
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
    implementation 'com.github.METADIUM:iitp-verifiable-sdk:0.1.2'
}
```


## Use it

### DID 생성

메일로 전달한 [metadium-cli-keygen](https://github.com/METADIUM/static/raw/master/metadium-cli-keygen-0.1.4.jar) 다운로드 후 DID 를 실행한다.  

```sh
> java -jar metadium-cli-keygen-0.1.4.jar
```

위와 같이 실행 하면 testnet DID 가 생성되며 해당 정보는 같은 디렉토리에 zip 파일로 생성됩니다.  
zip 파일은 압축을 풀면 (암호: 1234) 아래와 같은 텍스트 파일이 있습니다.

```text
##################################################################################
# ©Metadium. All Rights Reserved.
# 본 스크립트는 메타디움 testnet 에서 키, META_ID 생성, 메타디움에 등록 및 검증한 결과를 보여줍니다.
# 1. 키 생성(ECDSA secp256k1) (프라이빗키/퍼블릭키)
# 2. META_ID, DID 생성 후 메타디움 등록
# 3. 생성된 퍼블릭키를 메타디움에 등록
# 4. 생성된 DID를 DID Resolver로 검증한 결과
# 5. JWT를 생성된 프라이빗키로 서명하고 메타디움에 등록된 퍼블릭키로 검증한 결과
##################################################################################

* 생성일시: 2020-08-27 15:37:41
* 네트워크: testnet

* privateKey: 99112055342888496742264562644577768694656389302437903946367340342732551839767
* privateKeyHex: db1f6f74d9e4634e9f79c717d860b7325f737a62cae853cf284daf5b8e3f6017
* publicKey: 7316272687047055364350216367081405110799597809425770181618202906944900080130722774687807120671463913917790521874038483313409874756490972195869710730238237
* publicKeyHex: 8bb1322aa34c1e0cd916256c2afa517100ca5500fcb2a2c8db00d7e722e5462218c5759437c37ac1b6c73c34e67f52030d84e1bd6788923a60a98fac4445991d
* address: 0x3c8f9ad9c0d6e737607a396f4dc87e8502a221ab
* metaId: 0x0000000000000000000000000000000000000000000000000000000000001bcf
* META_ID 등록 트랜잭션 해시: 0xb6ce409cab2aeb74d49489a9a08e7409a158a1ac11d85df1cc03ce07c9a2aa7f
* DID: did:meta:testnet:0000000000000000000000000000000000000000000000000000000000001bcf
* DID Resolver URL: https://testnetresolver.metadium.com/1.0/identifiers/did:meta:testnet:0000000000000000000000000000000000000000000000000000000000001bcf
* 퍼블릭키 등록 트랜잭션 해시: 0xaef7ac3102327a4886e20cb32e7ccb424ae44320528dcdc15e91abce0b0e5332
* JWT KeyId: did:meta:testnet:0000000000000000000000000000000000000000000000000000000000001bcf#MetaManagementKey#3c8f9ad9c0d6e737607a396f4dc87e8502a221ab
* jwk: {"kty":"EC","d":"2x9vdNnkY06feccX2GC3Ml9zemLK6FPPKE2vW44_YBc","crv":"P-256K","x":"i7EyKqNMHgzZFiVsKvpRcQDKVQD8sqLI2wDX5yLlRiI","y":"GMV1lDfDesG2xzw05n9SAw2E4b1niJI6YKmPrERFmR0"}
* 퍼블릭키 등록 검증결과: success
* JWT sign/verify 테스트 결과: success
```

실제 사용할 값

- DID : META DID
- JWT KeyId : Key ID
- privateKeyHex : Hex 인코딩 private key

### VC / VP 발급

#### META
```java
String ISSUER_DID = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000001bcf";
String ISSUER_KID = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000001bcf#MetaManagementKey#3c8f9ad9c0d6e737607a396f4dc87e8502a221ab";
ECPrivateKey ISSUER_PRIVATE_KEY = ECKeyUtils.toECPrivateKey(new BigInteger("fdcdca38d0c62f3564f90afdc4c04c1f936b9edf95b5d8841a70b40cc84cfd90", 16), "secp256k1"); // PrivateKey load

String USER_DID = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b";
String USER_KID = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511";
ECPrivateKey USER_PRIVATE_KEY = ECKeyUtils.toECPrivateKey(new BigInteger("86975dca6a36062768cf4b648b5b3f712caa2d1d61fa42520624a8e574788822", 16), "secp256k1"); // PrivateKey load

// 만료일
Calendar calendar = Calendar.getInstance();
calendar.add(Calendar.YEAR, 2);

// VC 발급 - Issuer 가 발급
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
String signedVc = new MetadiumSigner(ISSUER_DID, ISSUER_KID, ISSUER_PRIVATE_KEY).sign(vc); // issuer 의 DID 로 서명

// VP 생성 - 사용자가 VP 생성
VerifiablePresentation vp = new VerifiablePresentation();
vp.setTypes(Arrays.asList("PRESENTATION", "MyPresentation"));
vp.addVerifiableCredential(signedVc);
String signedVp = new MetadiumSigner(USER_DID, USER_KID, USER_PRIVATE_KEY).sign(vp); // 사용자의 DID 로 서명
```

#### ICON


#### INDY


### VC / VP 검증

현재는 META 만 검증 가능합니다  
ICON 은 방화벽 정책 등록 이후에 사용 가능  
INDY 는 별도로 verifier 추가가 필요함

```java
// 한번만 미리 설정
VerifiableVerifier.register("did:meta:", MetadiumVerifier.class);	// META
VerifiableVerifier.register("did:icon:", IconVerifier.class);		// ICON
VerifiableVerifier.setResolverUrl("https://testnetresolver.metadium.com"); // Set universal resolver (http://129.254.194.103:9000). 테스트로 META resolver

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
