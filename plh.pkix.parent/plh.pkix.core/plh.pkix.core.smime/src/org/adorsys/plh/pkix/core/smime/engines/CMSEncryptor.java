package org.adorsys.plh.pkix.core.smime.engines;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

public class CMSEncryptor {
	
	private CMSPart inputPart;
	private List<X509Certificate> recipientCertificates = new ArrayList<X509Certificate>();
	
	BuilderChecker checker = new BuilderChecker(CMSEncryptor.class);
	public CMSPart encrypt() {
        checker.checkDirty()
        	.checkNull(inputPart, recipientCertificates)
        	.checkEmpty(recipientCertificates);
        
        // envelope the dataStream
        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        
        // add recipients
        try {
	        for (X509Certificate recipient509Certificate : recipientCertificates) {
					edGen.addRecipientInfoGenerator(        				
							new JceKeyTransRecipientInfoGenerator(recipient509Certificate).setProvider(ProviderUtils.bcProvider));
			}
        } catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
        }

        OutputStream  envelopedOut = null;
		try {
			CMSPart outPart = CMSPart.instanceEmpty();
			envelopedOut = edGen.open(outPart.openStream(), 
					new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(ProviderUtils.bcProvider).build());
			inputPart.writeTo(envelopedOut);
			return outPart;
		} catch (CMSException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {
			IOUtils.closeQuietly(envelopedOut);
		}
	}
	public CMSEncryptor withInputPart(CMSPart inputPart) {
		this.inputPart = inputPart;
		return this;
	}

	public CMSEncryptor withRecipientCertificates(List<X509Certificate> recipientCertificates) {
		this.recipientCertificates.addAll(recipientCertificates);
		return this;
	}
}
