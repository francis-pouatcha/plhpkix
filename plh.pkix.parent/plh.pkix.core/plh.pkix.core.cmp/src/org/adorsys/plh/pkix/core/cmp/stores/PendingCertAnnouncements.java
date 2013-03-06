package org.adorsys.plh.pkix.core.cmp.stores;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.DERGeneralizedTime;

public class PendingCertAnnouncements {
	
	private static final String DIR_NAME = "pending_announcements";
	private final FileWrapper rootDir;
	
	private Map<BigInteger, PendingCertAnnouncementHandle> pendingCertAnnouncementHandles = new HashMap<BigInteger, PendingCertAnnouncementHandle>();
	private Map<BigInteger, PendingCertAnnouncementData> pendingCertAnnouncementCache = new HashMap<BigInteger, PendingCertAnnouncementData>();
	
	
	public PendingCertAnnouncements(FileWrapper parentDir) {
		this.rootDir = parentDir.newChild(DIR_NAME);
	}

	public void storePendingCertAnnouncement(BigInteger serial, PendingCertAnnouncementData pendingCertAnnouncementData){
		PendingCertAnnouncement pendingCertAnnouncement = pendingCertAnnouncementData.getPendingCertAnnouncement();
		DERGeneralizedTime announcementTime = pendingCertAnnouncement.getAnnouncementTime();
		Date antime = null;
		if(announcementTime!=null)
			try {
				antime = announcementTime.getDate();
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		DERGeneralizedTime announcedTime = pendingCertAnnouncement.getAnnouncedtTime();
		Date andTime=null;
		if(announcedTime!=null)
			try {
				andTime = announcedTime.getDate();
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		if(pendingCertAnnouncementHandles.containsKey(serial)){
			deletePendingCertAnnouncement(serial);
		}
		PendingCertAnnouncementHandle  pendingCertAnnouncementHandle = new PendingCertAnnouncementHandle(serial, antime,andTime);
		FileWrapper fileWrapper = rootDir.newChild(pendingCertAnnouncementHandle.getFileName());
		OutputStream outputStream = fileWrapper.newOutputStream();
		pendingCertAnnouncementData.writeTo(outputStream);
		IOUtils.closeQuietly(outputStream);
		pendingCertAnnouncementCache.put(serial, pendingCertAnnouncementData);
		pendingCertAnnouncementHandles.put(serial, pendingCertAnnouncementHandle);
	}	
	
	public void sentPendingCertAnnouncement(BigInteger serial){
		PendingCertAnnouncementData pendingCertAnnouncementData = loadPendingCertAnnouncement(serial);
		if(pendingCertAnnouncementData==null) return;
		PendingCertAnnouncement pendingCertAnnouncement = pendingCertAnnouncementData.getPendingCertAnnouncement();
		pendingCertAnnouncement = new PendingCertAnnouncement(pendingCertAnnouncement.getSerial(), 
				pendingCertAnnouncement.getCertificateChain(),
				pendingCertAnnouncement.getAnnouncementTime(), 
				new DERGeneralizedTime(new Date()));
		pendingCertAnnouncementData = new PendingCertAnnouncementData(pendingCertAnnouncement);
		storePendingCertAnnouncement(serial, pendingCertAnnouncementData);
	}

	public void deletePendingCertAnnouncement(BigInteger serial){
		if(!pendingCertAnnouncementHandles.containsKey(serial)) return;		
		pendingCertAnnouncementHandles.remove(serial);
		pendingCertAnnouncementCache.remove(serial);
			
		PendingCertAnnouncementHandle pendingCertAnnouncementHandle = pendingCertAnnouncementHandles.remove(serial);
		FileWrapper fileWrapper = rootDir.newChild(pendingCertAnnouncementHandle.getFileName());
		
		if(fileWrapper.exists())
			fileWrapper.delete();
	}
	
	public void loadPendingCertAnnouncements(){
		pendingCertAnnouncementHandles.clear();
		pendingCertAnnouncementCache.clear();
		String[] list = rootDir.list();
		for (String fileName : list) {
			loadPendingCertAnnouncementHandle(fileName);
		}
	}
	public void loadPendingCertAnnouncementHandle(String fileName){		
		PendingCertAnnouncementHandle pendingCertAnnouncementHandle = new PendingCertAnnouncementHandle(fileName);
		pendingCertAnnouncementHandles.put(pendingCertAnnouncementHandle.getSerial(), pendingCertAnnouncementHandle);
	}

	public PendingCertAnnouncementData loadPendingCertAnnouncement(PendingCertAnnouncementHandle pendingCertAnnouncementHandle){		
		BigInteger serial = pendingCertAnnouncementHandle.getSerial();
		if(pendingCertAnnouncementCache.containsKey(serial))
			return pendingCertAnnouncementCache.get(serial);
		
		FileWrapper fileWrapper = rootDir.newChild(pendingCertAnnouncementHandle.getFileName());
		if(!fileWrapper.exists()){
			throw new IllegalArgumentException("Missing underlying file");
		}

		InputStream newInputStream = fileWrapper.newInputStream();
		PendingCertAnnouncementData pendingCertAnnouncementData = new PendingCertAnnouncementData();
		pendingCertAnnouncementData.readFrom(newInputStream);
		IOUtils.closeQuietly(newInputStream);

		PendingCertAnnouncement pendingCertAnnouncement = pendingCertAnnouncementData.getPendingCertAnnouncement();
		PendingCertAnnouncementHandle prh = new PendingCertAnnouncementHandle(pendingCertAnnouncement);
		if(!pendingCertAnnouncementHandle.equals(prh))
			throw new SecurityException("request handle tempered. Handle from loaded object not matching in memory handle");
		pendingCertAnnouncementHandles.put(serial, pendingCertAnnouncementHandle);
		return pendingCertAnnouncementData;
	}
	public PendingCertAnnouncementData loadPendingCertAnnouncement(BigInteger certRequestId){
		if(!pendingCertAnnouncementHandles.containsKey(certRequestId)) return null;
		return loadPendingCertAnnouncement(pendingCertAnnouncementHandles.get(certRequestId));
	}
	
	public Collection<PendingCertAnnouncementHandle> listHandles(){
		return pendingCertAnnouncementHandles.values();
	}
}
