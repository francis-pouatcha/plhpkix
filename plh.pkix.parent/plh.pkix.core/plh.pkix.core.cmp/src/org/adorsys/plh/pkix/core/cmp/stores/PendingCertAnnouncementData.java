package org.adorsys.plh.pkix.core.cmp.stores;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionData;

public class PendingCertAnnouncementData implements ActionData {

	private PendingCertAnnouncement pendingCertAnnouncement;
	
	public PendingCertAnnouncementData(PendingCertAnnouncement pendingCertAnnouncement) {
		this.pendingCertAnnouncement = pendingCertAnnouncement;
	}

	public PendingCertAnnouncementData() {
	}

	protected PendingCertAnnouncement getPendingCertAnnouncement() {
		return pendingCertAnnouncement;
	}

	@Override
	public void writeTo(OutputStream outputStream) {
		ASN1StreamUtils.writeTo(pendingCertAnnouncement, outputStream);
	}

	@Override
	public void readFrom(InputStream inputStream) {
		pendingCertAnnouncement = PendingCertAnnouncement.getInstance(ASN1StreamUtils.readFrom(inputStream));
	}
}
