package org.adorsys.plh.pkix.core.cmp.stores;

import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.DERGeneralizedTime;

public class PendingResponses {
	
	private static final String dirRelativePath = "pending_requests";
	private final FilesContainer fileContainer;
	
	private Map<String, PendingResponseHandle> pendingResponseHandles = new HashMap<String, PendingResponseHandle>();
	private Map<String, PendingResponseData> pendingResponseCache = new HashMap<String, PendingResponseData>();
	
	public PendingResponses(FilesContainer fileContainer) {
		this.fileContainer = fileContainer;
	}

	public void storePendingResponse(String transactionID, PendingResponseData pendingResponseData){
		PendingResponse pendingResponse = pendingResponseData.getPendingResponse();
		DERGeneralizedTime responseTime = pendingResponse.getResponseTime();
		Date respT = null;
		if(responseTime!=null)
			try {
				respT = responseTime.getDate();
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		DERGeneralizedTime deliveryTime = pendingResponse.getDeliveryTime();
		Date delT=null;
		if(deliveryTime!=null)
			try {
				delT = deliveryTime.getDate();
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		if(pendingResponseHandles.containsKey(transactionID)){
			deletePendingResponse(transactionID);
		}

		PendingResponseHandle pendingResponseHandle = new PendingResponseHandle(transactionID, respT, delT);
		FileWrapper fileWrapper = fileContainer.newFile(dirRelativePath, pendingResponseHandle.getFileName());
		OutputStream outputStream = fileWrapper.newOutputStream();
		pendingResponseData.writeTo(outputStream);
		IOUtils.closeQuietly(outputStream);
		pendingResponseCache.put(transactionID, pendingResponseData);
		pendingResponseHandles.put(transactionID, pendingResponseHandle);
	}	
	
	public void diliverPendingResponse(String transactionID)
	{
		PendingResponseData pendingResponseData = loadPendingResponse(transactionID);
		if(pendingResponseData==null) return;
		PendingResponse pendingResponse = pendingResponseData.getPendingResponse();
		pendingResponse.setDeliveryTime(new DERGeneralizedTime(new Date()));
		storePendingResponse(transactionID, pendingResponseData);
	}

	public void deletePendingResponse(String transactionID){
		if(!pendingResponseHandles.containsKey(transactionID)) return;		
		pendingResponseHandles.remove(transactionID);
		pendingResponseCache.remove(transactionID);
			
		PendingResponseHandle pendingResponseHandle = pendingResponseHandles.remove(transactionID);
		FileWrapper fileWrapper = fileContainer.newFile(dirRelativePath, pendingResponseHandle.getFileName());
		
		if(fileWrapper.exists())
			fileWrapper.delete();
	}
	
	public void loadPollRequests(){
		pendingResponseHandles.clear();
		pendingResponseCache.clear();
		FileWrapper parent = fileContainer.newFile(dirRelativePath);
		String[] list = parent.list();
		for (String fileName : list) {
			loadPendingResponseHandle(fileName);
		}
	}
	public void loadPendingResponseHandle(String fileName){		
		PendingResponseHandle pendingResponseHandle = new PendingResponseHandle(fileName);
		pendingResponseHandles.put(pendingResponseHandle.getTransactionID(), pendingResponseHandle);
	}

	public PendingResponseData loadPendingResponse(PendingResponseHandle pendingResponseHandle){		
		String transactionID = pendingResponseHandle.getTransactionID();
		if(pendingResponseCache.containsKey(transactionID))
			return pendingResponseCache.get(transactionID);
		
		FileWrapper fileWrapper = fileContainer.newFile(dirRelativePath,pendingResponseHandle.getFileName());
		if(!fileWrapper.exists()){
			throw new IllegalArgumentException("Missing underlying file");
		}

		InputStream newInputStream = fileWrapper.newInputStream();
		PendingResponseData pendingResponseData = new PendingResponseData();
		pendingResponseData.readFrom(newInputStream);
		IOUtils.closeQuietly(newInputStream);
		
		PendingResponse pendingResponse = pendingResponseData.getPendingResponse();
		PendingResponseHandle prh = new PendingResponseHandle(pendingResponse);
		if(!pendingResponseHandle.equals(prh))
			throw new SecurityException("Response handle tempered. Handle from loaded object not matching in memory handle");
		pendingResponseHandles.put(transactionID, pendingResponseHandle);
		return pendingResponseData;
	}
	public PendingResponseData loadPendingResponse(String transactionID){
		if(!pendingResponseHandles.containsKey(transactionID)) return null;
		return loadPendingResponse(pendingResponseHandles.get(transactionID));
	}
}
