package org.adorsys.plh.pkix.core.cmp.utils;

import java.io.IOException;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;

public class PkiMessageBuilder {

	private byte[] pkiMessageBytes;
	
	BuilderChecker checker = new BuilderChecker(PkiMessageBuilder.class);
	public GeneralPKIMessage build(){
		checker.checkDirty()
			.checkNull(pkiMessageBytes);
			
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
