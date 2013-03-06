package org.adorsys.plh.pkix.core.cmp.certann;

import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;

public class CertificateAnnouncementBuilder {

	BuilderChecker checker = new BuilderChecker(CertificateAnnouncementBuilder.class);
	public PKIMessage build(PrivateKeyEntry privateKeyEntry) {
		checker.checkDirty()
			.checkNull(privateKeyEntry);

		// no announcement of a self signed certificate.
		Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
		if(certificateChain.length<2)
			throw new IllegalStateException("No Announcement of a self signed certificate");
		
		X509CertificateHolder subjectCertificate = V3CertificateUtils.getX509CertificateHolder(certificateChain[0]);
		X509CertificateHolder issuerCertificate = V3CertificateUtils.getX509CertificateHolder(certificateChain[1]);

		GeneralName subject = new GeneralName(X500NameHelper.readSubjectDN(subjectCertificate));
		byte[] subjectKeyId = KeyIdUtils.readSubjectKeyIdentifierAsByteString(subjectCertificate);
		
		GeneralName receiver = new GeneralName(subjectCertificate.getIssuer());
		byte[] issuerKeyId = KeyIdUtils.readSubjectKeyIdentifierAsByteString(issuerCertificate);

		ContentSigner subjectSigner = V3CertificateUtils.getContentSigner(privateKeyEntry.getPrivateKey(), "MD5WithRSAEncryption");

		CMPCertificate cmpCertificate = new CMPCertificate(subjectCertificate.toASN1Structure());

		ProtectedPKIMessage mainMessage;
		try {
			mainMessage = new ProtectedPKIMessageBuilder(subject, receiver)
					.setBody(new PKIBody(PKIBody.TYPE_CERT_ANN, cmpCertificate))
					.addCMPCertificate(subjectCertificate)
					.setMessageTime(new Date())
					.setSenderKID(subjectKeyId)
					.setRecipKID(issuerKeyId)
					.setSenderNonce(UUIDUtils.newUUIDAsBytes())
					.setTransactionID(UUIDUtils.newUUIDAsBytes())
					.build(subjectSigner);
		} catch (CMPException e) {
			throw new IllegalStateException(e);
		}

		return mainMessage.toASN1Structure();
	}
}
