package com.iitp.verifiable.signer;

import com.iitp.verifiable.Verifiable;

public interface VerifiableSigner {
	String sign(Verifiable verifiable) throws Exception;
}
