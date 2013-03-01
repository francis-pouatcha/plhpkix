package org.adorsys.plh.pkix.core.cmp.stores;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.DERGeneralizedTime;

public class PendingRequests {
	
	private static final String dirRelativePath = "pending_requests";
	private final FilesContainer fileContainer;
	
	private Map<BigInteger, PendingRequestHandle> pendingRequestHandles = new HashMap<BigInteger, PendingRequestHandle>();
	private Map<BigInteger, PendingRequestData> pendingRequestCache = new HashMap<BigInteger, PendingRequestData>();
	
	
	public PendingRequests(FilesContainer fileContainer) {
		this.fileContainer = fileContainer;
	}

	public void storePollRequestHolder(BigInteger certReqId, PendingRequestData pendingRequestData){
		PendingRequest pendingRequest = pendingRequestData.getPendingRequest();
		DERGeneralizedTime nextPoll = pendingRequest.getNextPoll();
		Date nxtPl = null;
		if(nextPoll!=null)
			try {
				nxtPl = nextPoll.getDate();
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		DERGeneralizedTime disposed = pendingRequest.getDisposed();
		Date disp=null;
		if(disposed!=null)
			try {
				disp = disposed.getDate();
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		if(pendingRequestHandles.containsKey(certReqId)){
			deletePendingRequest(certReqId);
		}
		PendingRequestHandle  pendingRequestHandle = new PendingRequestHandle(certReqId, nxtPl,disp);
		FileWrapper fileWrapper = fileContainer.newFile(dirRelativePath, pendingRequestHandle.getFileName());
		OutputStream outputStream = fileWrapper.newOutputStream();
		pendingRequestData.writeTo(outputStream);
		IOUtils.closeQuietly(outputStream);
		pendingRequestCache.put(certReqId, pendingRequestData);
		pendingRequestHandles.put(certReqId, pendingRequestHandle);
	}	
	
	public void disposePendingRequest(BigInteger certReqId){
		PendingRequestData pendingRequestData = loadPendingRequest(certReqId);
		if(pendingRequestData==null) return;
		PendingRequest pendingRequest = pendingRequestData.getPendingRequest();
		pendingRequest.setDisposed(new DERGeneralizedTime(new Date()));
		storePollRequestHolder(certReqId, pendingRequestData);
	}

	public void deletePendingRequest(BigInteger certReqId){
		if(!pendingRequestHandles.containsKey(certReqId)) return;		
		pendingRequestHandles.remove(certReqId);
		pendingRequestCache.remove(certReqId);
			
		PendingRequestHandle pendingRequestHandle = pendingRequestHandles.remove(certReqId);
		FileWrapper fileWrapper = fileContainer.newFile(dirRelativePath, pendingRequestHandle.getFileName());
		
		if(fileWrapper.exists())
			fileWrapper.delete();
	}
	
	public void loadPollRequests(){
		pendingRequestHandles.clear();
		pendingRequestCache.clear();
		FileWrapper parent = fileContainer.newFile(dirRelativePath);
		String[] list = parent.list();
		for (String fileName : list) {
			loadPendingRequestHandle(fileName);
		}
	}
	public void loadPendingRequestHandle(String fileName){		
		PendingRequestHandle pendingRequestHandle = new PendingRequestHandle(fileName);
		pendingRequestHandles.put(pendingRequestHandle.getCertReqId(), pendingRequestHandle);
	}

	public PendingRequestData loadPendingRequest(PendingRequestHandle pendingRequestHandle){		
		BigInteger certReqId = pendingRequestHandle.getCertReqId();
		if(pendingRequestCache.containsKey(certReqId))
			return pendingRequestCache.get(certReqId);
		
		FileWrapper fileWrapper = fileContainer.newFile(dirRelativePath,pendingRequestHandle.getFileName());
		if(!fileWrapper.exists()){
			throw new IllegalArgumentException("Missing underlying file");
		}

		InputStream newInputStream = fileWrapper.newInputStream();
		PendingRequestData pendingRequestData = new PendingRequestData();
		pendingRequestData.readFrom(newInputStream);
		IOUtils.closeQuietly(newInputStream);

		PendingRequest pendingRequest = pendingRequestData.getPendingRequest();
		PendingRequestHandle prh = new PendingRequestHandle(pendingRequest);
		if(!pendingRequestHandle.equals(prh))
			throw new SecurityException("request handle tempered. Handle from loaded object not matching in memory handle");
		pendingRequestHandles.put(certReqId, pendingRequestHandle);
		return pendingRequestData;
	}
	public PendingRequestData loadPendingRequest(BigInteger certRequestId){
		if(!pendingRequestHandles.containsKey(certRequestId)) return null;
		return loadPendingRequest(pendingRequestHandles.get(certRequestId));
	}
}
