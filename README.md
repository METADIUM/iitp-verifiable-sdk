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

### VC / VP 발급

#### META
```java
String ISSUER_DID = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382";
String ISSUER_KID = "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000000382#MetaManagementKey#59ddc27f5bc6983458eac013b1e771d11c908683";
ECPrivateKey ISSUER_PRIVATE_KEY = ...;

String USER_DID = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b";
String USER_KID = "did:meta:testnet:000000000000000000000000000000000000000000000000000000000000054b#MetaManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511";
ECPrivateKey USER_PRIVATE_KEY = ...;

// 만료일
Calendar calendar = Calendar.getInstance();
calendar.add(Calendar.YEAR, 2);

// VC 발급
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

// VP 발급
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
