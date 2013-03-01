package org.adorsys.plh.pkix.core.cmp.certrequest;

import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.message.CertificateChain;
import org.adorsys.plh.pkix.core.cmp.message.CertificateChainActionData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncement;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncementData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncements;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.action.ActionProcessor;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.x509.Certificate;

public class CertificationReplyImportActionProcessor implements
		ActionProcessor {

	private final BuilderChecker checker = new BuilderChecker(CertificationReplyImportActionProcessor.class);
	@Override
	public void process(ActionContext actionContext) {

		CertificateChainActionData actionData = actionContext.get(CertificateChainActionData.class,null);
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class,null);
		PendingCertAnnouncements pendingCertAnns = actionContext.get(PendingCertAnnouncements.class,null);
		
		checker.checkNull(actionData,keyStoreWraper,pendingCertAnns);
		
		// Import the certificate into key store
		CertificateChain certificateChain = actionData.getCertificateChain();
		Certificate[] certArray = certificateChain.toCertArray();
		keyStoreWraper.importIssuedCertificate(certArray);

		// Store th certificate for publication
		DERGeneralizedTime announcementTime = new DERGeneralizedTime(new Date());
		Certificate certificate = certArray[0];
		ASN1Integer serialNumber = certificate.getSerialNumber();
		PendingCertAnnouncement pendingCertAnnouncement = 
				new PendingCertAnnouncement(serialNumber, certificate, announcementTime);
		PendingCertAnnouncementData pendingCertAnnouncementData =
				new PendingCertAnnouncementData(pendingCertAnnouncement);
		pendingCertAnns.storePendingCertAnnouncement(serialNumber.getPositiveValue(), pendingCertAnnouncementData);
	}
}
