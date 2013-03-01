package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;

public class CMSPWDStreamEncryptor {
	
	private OutputStream outputStream;
	
	BuilderChecker checker = new BuilderChecker(CMSPWDStreamEncryptor.class);
	public OutputStream toEncryptingOutputStream(char[] password) {
        checker.checkDirty().checkNull(outputStream,password);
        
        // envelope the dataStream
        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        
        edGen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(CMSAlgorithm.DES_EDE3_CBC, password)
        	.setProvider(ProviderUtils.bcProvider));
 
		try {
			return edGen.open(outputStream, 
					new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
						.setProvider(ProviderUtils.bcProvider)
						.build());
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	public CMSPWDStreamEncryptor withOutputStream(OutputStream outputStream) {
		this.outputStream = outputStream;
		return this;
	}
}
