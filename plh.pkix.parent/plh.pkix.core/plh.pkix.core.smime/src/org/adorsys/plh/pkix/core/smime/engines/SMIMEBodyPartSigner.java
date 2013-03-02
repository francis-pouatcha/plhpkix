package org.adorsys.plh.pkix.core.smime.engines;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

public class SMIMEBodyPartSigner {

	private X500Name issuerName;
	private MimeBodyPart mimeBodyPart;
	
	private final BuilderChecker checker = new BuilderChecker(SMIMEBodyPartSigner.class);
	public MimeBodyPart sign(PrivateKeyEntry senderPrivateKeyEntry)
			throws SMIMEException, MessagingException
	{
		checker.checkDirty()
			.checkNull(senderPrivateKeyEntry, issuerName, mimeBodyPart);
		
		Certificate[] certificateChain = senderPrivateKeyEntry.getCertificateChain();
		List<X509Certificate> senderCertificateChain = V3CertificateUtils.convert(certificateChain);

		// create a CertStore containing the certificates we want carried
		// in the signature
		Store senderCertStore;
		try {
			senderCertStore = new JcaCertStore(senderCertificateChain);
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		}

		// create some smime capabilities in case someone wants to respond
		ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
		SMIMECapabilityVector caps = new SMIMECapabilityVector();

		caps.addCapability(SMIMECapability.dES_EDE3_CBC);
		caps.addCapability(SMIMECapability.rC2_CBC, 128);
		caps.addCapability(SMIMECapability.dES_CBC);

		X509Certificate senderCertificate = senderCertificateChain.get(0);
		signedAttrs.add(new SMIMECapabilitiesAttribute(caps));
		// add an encryption key preference for encrypted responses -
		// normally this would be different from the signing certificate...
		IssuerAndSerialNumber issAndSer = new IssuerAndSerialNumber(issuerName,
				senderCertificate.getSerialNumber());
		signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(issAndSer));

		// create the generator for creating an smime/signed message
		SMIMESignedGenerator gen = new SMIMESignedGenerator();

		// add a signer to the generator - this specifies we are using SHA1 and
		// adding the smime attributes above to the signed attributes that
		// will be generated as part of the signature. The encryption algorithm
		// used is taken from the key - in this RSA with PKCS1Padding
		try {
			gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
					.setProvider(ProviderUtils.bcProvider)
					.setSignedAttributeGenerator(new AttributeTable(signedAttrs))
					.build("SHA1withRSA", senderPrivateKeyEntry.getPrivateKey(), senderCertificate));
		} catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		// add our pool of certs and cerls (if any) to go with the signature
		gen.addCertificates(senderCertStore);

		// extract the multipart object from the SMIMESigned object.
		return gen.generateEncapsulated(mimeBodyPart);
	}

	public SMIMEBodyPartSigner withIssuerName(X500Name issuer) {
		this.issuerName = issuer;
		return this;
	}

	public SMIMEBodyPartSigner withMimeBodyPart(MimeBodyPart mimeBodyPart) {
		this.mimeBodyPart = mimeBodyPart;
		return this;
	}
}
