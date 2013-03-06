package org.adorsys.plh.pkix.core.cmp.initrequest.sender;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.OutgoingRequestHandle;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;

/**
 * Manages outgoing certification requests. Before the request is sent out
 * it is stored here so if the is any exception, it is documented in the 
 * request.
 * 
 * @author francis
 *
 */
public class OutgoingInitializationRequests {
	
	private static final String DIRRELATIVEPATH = "outgoing_registration_requests";
	private final FileWrapper rootDir;
	
	private Map<BigInteger, OutgoingRequestHandle> outgoingRequestHandles = new HashMap<BigInteger, OutgoingRequestHandle>();
	private Map<BigInteger, OutgoingInitializationRequestData> outgoingRequestCache = new HashMap<BigInteger, OutgoingInitializationRequestData>();
	
	public OutgoingInitializationRequests(FileWrapper accountDir) {
		this.rootDir = accountDir.newChild(DIRRELATIVEPATH);
	}

	public void storeRequest(BigInteger certReqId, OutgoingInitializationRequestData requestData){
		OutgoingRequest initializationRequest = requestData.getOutgoingRequest();
		OutgoingRequestHandle outgoingRequestHandle = new OutgoingRequestHandle(initializationRequest);
		if(outgoingRequestHandles.containsKey(certReqId)){
			deleteRequest(certReqId);
		}
		FileWrapper fileWrapper = rootDir.newChild(outgoingRequestHandle.getFileName());
		OutputStream outputStream = fileWrapper.newOutputStream();
		requestData.writeTo(outputStream);
		IOUtils.closeQuietly(outputStream);
		outgoingRequestCache.put(certReqId, requestData);
		outgoingRequestHandles.put(certReqId, outgoingRequestHandle);
	}	

	public void deleteRequest(BigInteger certReqId){
		if(!outgoingRequestHandles.containsKey(certReqId)) return;		
		OutgoingRequestHandle requestHandle = outgoingRequestHandles.remove(certReqId);
		outgoingRequestCache.remove(certReqId);
			
		FileWrapper fileWrapper = rootDir.newChild(requestHandle.getFileName());
		
		if(fileWrapper.exists())
			fileWrapper.delete();
	}
	
	public void loadPollRequests(){
		outgoingRequestHandles.clear();
		outgoingRequestCache.clear();
		String[] list = rootDir.list();
		for (String fileName : list) {
			loadRequestHandle(fileName);
		}
	}
	public void loadRequestHandle(String fileName){		
		OutgoingRequestHandle registrationRequestHandle = new OutgoingRequestHandle(fileName);
		outgoingRequestHandles.put(registrationRequestHandle.getCertReqId(), registrationRequestHandle);
	}

	public OutgoingInitializationRequestData loadPendingRequest(OutgoingRequestHandle pendingRequestHandle){		
		BigInteger certReqId = pendingRequestHandle.getCertReqId();
		if(outgoingRequestCache.containsKey(certReqId))
			return outgoingRequestCache.get(certReqId);
		
		FileWrapper fileWrapper = rootDir.newChild(pendingRequestHandle.getFileName());
		if(!fileWrapper.exists()){
			throw new IllegalArgumentException("Missing underlying file");
		}

		InputStream newInputStream = fileWrapper.newInputStream();
		OutgoingInitializationRequestData pendingRequestData = new OutgoingInitializationRequestData();
		pendingRequestData.readFrom(newInputStream);
		IOUtils.closeQuietly(newInputStream);

		OutgoingRequest pendingRequest = pendingRequestData.getOutgoingRequest();
		OutgoingRequestHandle prh = new OutgoingRequestHandle(pendingRequest);
		if(!pendingRequestHandle.equals(prh))
			throw new SecurityException("request handle tempered. Handle from loaded object not matching in memory handle");
		outgoingRequestHandles.put(certReqId, pendingRequestHandle);
		return pendingRequestData;
	}
	public OutgoingInitializationRequestData loadRequest(BigInteger certRequestId){
		if(!outgoingRequestHandles.containsKey(certRequestId)) return null;
		return loadPendingRequest(outgoingRequestHandles.get(certRequestId));
	}
	
	public Collection<OutgoingRequestHandle> listHandles(){
		return outgoingRequestHandles.values();
	}
}
