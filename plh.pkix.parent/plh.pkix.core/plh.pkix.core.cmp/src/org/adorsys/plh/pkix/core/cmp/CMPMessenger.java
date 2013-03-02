package org.adorsys.plh.pkix.core.cmp;

import org.bouncycastle.asn1.cmp.PKIMessage;

public interface CMPMessenger {

	public void announceCertificate(PKIMessage certAnnouncement);

	public void sendPollRequest(PKIMessage pendingPollRequestMessage);
}
