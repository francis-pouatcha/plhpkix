package org.adorsys.plh.pkix.core.cmp.certann;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.Collection;
import java.util.Date;

import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.message.CertificateChain;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncement;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncementData;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncementHandle;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncements;
import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * When activated, read pending cert announcement and process them.
 * 
 * @author francis
 *
 */
public class CertAnnouncementJob implements Runnable{

	private ActionContext actionContext;
	
	BuilderChecker checker = new BuilderChecker(CertAnnouncementJob.class);
	@Override
	public void run() {
		PendingCertAnnouncements pendingCertAnnouncements = actionContext.get(PendingCertAnnouncements.class);
		KeyStoreWraper keyStoreWraper = actionContext.get(KeyStoreWraper.class);
		checker.checkDirty().checkNull(pendingCertAnnouncements, keyStoreWraper);
		pendingCertAnnouncements.loadPendingCertAnnouncements();
		Collection<PendingCertAnnouncementHandle> handles = pendingCertAnnouncements.listHandles();
		for (PendingCertAnnouncementHandle pendingCertAnnouncementHandle : handles) {
			if(pendingCertAnnouncementHandle.getAnnouncedtTime()!=null) continue;
			PendingCertAnnouncementData pendingCertAnnouncementData = pendingCertAnnouncements.loadPendingCertAnnouncement(pendingCertAnnouncementHandle);
			PendingCertAnnouncement pendingCertAnnouncement = pendingCertAnnouncementData.getPendingCertAnnouncement();
			CertificateChain certificateChain = pendingCertAnnouncement.getCertificateChain();
			Certificate[] certArray = certificateChain.toCertArray();
			if(certArray.length<2) {// no cert announcement needed for self signed certificate
				setAcnnounced(pendingCertAnnouncement, pendingCertAnnouncements);
				continue;
			}
			X509CertificateHolder issuerCertificate = new X509CertificateHolder(certArray[1]);
			// POP private key must be used for the cert announcement, even if not an smim key
			PrivateKeyEntry privateKeyEntry = keyStoreWraper.findMessagePrivateKeyEntryByIssuerCertificate(issuerCertificate);
			PKIMessage certAnnouncementMessage = new CertificateAnnouncementBuilder()
				.build(privateKeyEntry);
			CMPMessenger cmpMessenger = actionContext.get(CMPMessenger.class);
			try {
				cmpMessenger.announceCertificate(certAnnouncementMessage);
				// set announced
				setAcnnounced(pendingCertAnnouncement, pendingCertAnnouncements);				
			} catch(Exception ex){
				// TODO log message for bacth processing.// might be in the cert ann object
			}
		}
	}
	
	private void setAcnnounced(PendingCertAnnouncement pendingCertAnnouncement, PendingCertAnnouncements pendingCertAnnouncements){
		pendingCertAnnouncement = new PendingCertAnnouncement(pendingCertAnnouncement.getSerial(), 
				pendingCertAnnouncement.getCertificateChain(), pendingCertAnnouncement.getAnnouncementTime(),
				new DERGeneralizedTime(new Date()));
		PendingCertAnnouncementData pendingCertAnnouncementData = new PendingCertAnnouncementData(pendingCertAnnouncement);
		pendingCertAnnouncements.storePendingCertAnnouncement(pendingCertAnnouncement.getSerial().getPositiveValue(), pendingCertAnnouncementData);		
	}

}
