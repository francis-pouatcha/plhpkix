package org.adorsys.plh.pkix.core.cmp.stores;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;

public class PendingCertAnnouncementHandle {

	private final BigInteger serial;
	private final Date announcementTime;
	private final String fileName;
	private final Date announcedtTime;
	
	public PendingCertAnnouncementHandle(BigInteger serial, Date announcementTime, Date announcedtTime) {
		super();
		this.announcementTime = announcementTime;
		this.serial = serial;
		this.fileName = PendingCertAnnFileNameHelper.makeFileName(serial, announcementTime, announcedtTime);
		this.announcedtTime=announcedtTime;
	}
	public PendingCertAnnouncementHandle(PendingCertAnnouncement pendingCertAnnouncement) {
		ASN1Integer serialNumber = pendingCertAnnouncement.getSerial();
		serial = serialNumber.getPositiveValue();
		try {
			DERGeneralizedTime np = pendingCertAnnouncement.getAnnouncementTime();
			announcementTime= np==null?null:np.getDate();
			DERGeneralizedTime d = pendingCertAnnouncement.getAnnouncedtTime();
			announcedtTime= d==null?null:d.getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
		this.fileName = PendingCertAnnFileNameHelper.makeFileName(serial, announcementTime, announcedtTime);
	}
	public PendingCertAnnouncementHandle(String fileName) {
		this.fileName = fileName;
		this.serial = PendingCertAnnFileNameHelper.getSerial(fileName);
		this.announcementTime=PendingCertAnnFileNameHelper.getAnnouncementTime(fileName);
		this.announcedtTime=PendingCertAnnFileNameHelper.getAnnouncedtTime(fileName);
	}
	public String getFileName() {
		return fileName;
	}
	public BigInteger getSerial() {
		return serial;
	}
	public Date getAnnouncementTime() {
		return announcementTime;
	}
	public Date getAnnouncedtTime() {
		return announcedtTime;
	}
	
	
}
