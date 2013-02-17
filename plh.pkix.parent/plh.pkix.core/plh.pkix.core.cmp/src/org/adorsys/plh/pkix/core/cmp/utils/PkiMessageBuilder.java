package org.adorsys.plh.pkix.core.cmp.utils;

import java.io.IOException;

import org.bouncycastle.cert.cmp.GeneralPKIMessage;

public class PkiMessageBuilder {

	private byte[] pkiMessageBytes;
	
	public GeneralPKIMessage build(){
		assert pkiMessageBytes!=null: "missing pkiMessageBytes.";
		try {
			return new GeneralPKIMessage(pkiMessageBytes);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}				
	}
	
	public PkiMessageBuilder withPkiMessageBytes(byte[] pkiMessageBytes){
		this.pkiMessageBytes = pkiMessageBytes;
		return this;
	}
}
