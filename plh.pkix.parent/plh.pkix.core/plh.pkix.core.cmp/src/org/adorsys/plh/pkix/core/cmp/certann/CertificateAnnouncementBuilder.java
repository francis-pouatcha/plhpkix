package org.adorsys.plh.pkix.core.cmp.certann;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.PrivateKeyUtils;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateAnnouncementBuilder {

	BuilderChecker checker = new BuilderChecker(CertificateAnnouncementBuilder.class);
	public PKIMessage build(PrivateKeyEntry privateKeyEntry) {
		checker.checkDirty()
			.checkNull(privateKeyEntry);
		
		X509CertificateHolder subjectCertificate = PrivateKeyUtils
				.getX509CertificateHolder(privateKeyEntry);
		GeneralName subject = new GeneralName(subjectCertificate.getSubject());
		GeneralName server = new GeneralName(PlhCMPSystem.getServerName());

		ContentSigner subjectSigner;
		try {
			subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption")
					.setProvider(ProviderUtils.bcProvider).build(
							privateKeyEntry.getPrivateKey());
		} catch (OperatorCreationException e) {
			throw new IllegalStateException(e);
		}

		byte[] subjectKeyId = KeyIdUtils
				.readSubjectKeyIdentifierAsByteString(subjectCertificate);
		CMPCertificate cmpCertificate = new CMPCertificate(
				subjectCertificate.toASN1Structure());

		ProtectedPKIMessage mainMessage;
		try {
			mainMessage = new ProtectedPKIMessageBuilder(subject, server)
					.setBody(new PKIBody(PKIBody.TYPE_CERT_ANN, cmpCertificate))
					.addCMPCertificate(subjectCertificate)
					.setMessageTime(new Date()).setSenderKID(subjectKeyId)
					.setSenderNonce(UUIDUtils.newUUIDAsBytes())
					.setTransactionID(UUIDUtils.newUUIDAsBytes())
					.build(subjectSigner);
		} catch (CMPException e) {
			throw new IllegalStateException(e);
		}

		return mainMessage.toASN1Structure();
	}
}
