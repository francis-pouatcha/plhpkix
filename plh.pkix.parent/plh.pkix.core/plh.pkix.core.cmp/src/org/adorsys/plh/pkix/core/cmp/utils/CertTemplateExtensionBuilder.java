package org.adorsys.plh.pkix.core.cmp.utils;

import java.io.IOException;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;

/**
 * Build a certificate template with information passed to this object.
 * 
 * The object shall not be reused. After the build method is called, this object is not reusable.
 * 
 * 
 * @author francis
 *
 */
public class CertTemplateExtensionBuilder {

	private boolean ca;

	private int keyUsage=-1;
	private boolean keyUsageSet = false;

	private GeneralNames subjectAltName;

	private BuilderChecker checker = new BuilderChecker(CertTemplateExtensionBuilder.class);
	public Extensions build() {
		checker.checkDirty();

		BasicConstraints basicConstraints = null;
		if(ca){
			// self signed ca certificate
			basicConstraints = new BasicConstraints(true);
			withKeyUsage(KeyUsage.keyCertSign);
		} else {
			basicConstraints = new BasicConstraints(false);
		}


		ExtensionsGenerator extGenerator = new ExtensionsGenerator();

		try {
			extGenerator.addExtension(X509Extension.basicConstraints,true, basicConstraints);

			if(keyUsageSet){
				extGenerator.addExtension(X509Extension.keyUsage,
						true, new KeyUsage(this.keyUsage));
			}

			if(subjectAltName!=null)
				extGenerator.addExtension(X509Extension.subjectAlternativeName, false, subjectAltName);
		} catch (CertIOException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}

		return extGenerator.generate();
	}

	public CertTemplateExtensionBuilder withCa(boolean ca) {
		this.ca = ca;
		return this;
	}

	public CertTemplateExtensionBuilder withKeyUsage(int keyUsage) {
		if(keyUsageSet){
			this.keyUsage=this.keyUsage|keyUsage;
		} else {
			this.keyUsage=keyUsage;
			keyUsageSet=true;
		}
		return this;
	}

	public CertTemplateExtensionBuilder withSubjectAltName(GeneralNames subjectAltName) {
		this.subjectAltName = subjectAltName;
		return this;
	}
}
