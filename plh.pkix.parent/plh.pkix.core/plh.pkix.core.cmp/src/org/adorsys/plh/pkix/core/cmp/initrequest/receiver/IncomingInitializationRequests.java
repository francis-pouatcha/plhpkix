package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequestHandle;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;

/**
 * Manages incoming certification requests. Before the request is sent out
 * it is stored here so if the is any exception, it is documented in the 
 * request.
 * 
 * @author francis
 *
 */
public class IncomingInitializationRequests {
	
	private static final String DIRRELATIVEPATH = "incoming_initialization_requests";
	private final FileWrapper rootDir;
	
	private Map<BigInteger, IncomingRequestHandle> incomingRequestHandles = new HashMap<BigInteger, IncomingRequestHandle>();
	private Map<BigInteger, IncomingInitializationRequestData> incomingRequestCache = new HashMap<BigInteger, IncomingInitializationRequestData>();
	
	public IncomingInitializationRequests(FileWrapper accountDir) {
		this.rootDir = accountDir.newChild(DIRRELATIVEPATH);
	}

	public void storeRequest(BigInteger certReqId, IncomingInitializationRequestData requestData){
		IncomingRequest initializationRequest = requestData.getIncomingRequest();
		IncomingRequestHandle incomingRequestHandle = new IncomingRequestHandle(initializationRequest);
		if(incomingRequestHandles.containsKey(certReqId)){
			deleteRequest(certReqId);
		}
		FileWrapper fileWrapper = rootDir.newChild(incomingRequestHandle.getFileName());
		OutputStream outputStream = fileWrapper.newOutputStream();
		requestData.writeTo(outputStream);
		IOUtils.closeQuietly(outputStream);
		incomingRequestCache.put(certReqId, requestData);
		incomingRequestHandles.put(certReqId, incomingRequestHandle);
	}	

	public void deleteRequest(BigInteger certReqId){
		if(!incomingRequestHandles.containsKey(certReqId)) return;		
		IncomingRequestHandle requestHandle = incomingRequestHandles.remove(certReqId);
		incomingRequestCache.remove(certReqId);
			
		FileWrapper fileWrapper = rootDir.newChild(requestHandle.getFileName());
		
		if(fileWrapper.exists())
			fileWrapper.delete();
	}
	
	public void loadPollRequests(){
		incomingRequestHandles.clear();
		incomingRequestCache.clear();
		String[] list = rootDir.list();
		for (String fileName : list) {
			loadRequestHandle(fileName);
		}
	}
	public void loadRequestHandle(String fileName){		
		IncomingRequestHandle registrationRequestHandle = new IncomingRequestHandle(fileName);
		incomingRequestHandles.put(registrationRequestHandle.getCertReqId(), registrationRequestHandle);
	}

	public IncomingInitializationRequestData loadPendingRequest(IncomingRequestHandle pendingRequestHandle){		
		BigInteger certReqId = pendingRequestHandle.getCertReqId();
		if(incomingRequestCache.containsKey(certReqId))
			return incomingRequestCache.get(certReqId);
		
		FileWrapper fileWrapper = rootDir.newChild(pendingRequestHandle.getFileName());
		if(!fileWrapper.exists()){
			throw new IllegalArgumentException("Missing underlying file");
		}

		InputStream newInputStream = fileWrapper.newInputStream();
		IncomingInitializationRequestData pendingRequestData = new IncomingInitializationRequestData();
		pendingRequestData.readFrom(newInputStream);
		IOUtils.closeQuietly(newInputStream);

		IncomingRequest pendingRequest = pendingRequestData.getIncomingRequest();
		IncomingRequestHandle prh = new IncomingRequestHandle(pendingRequest);
		if(!pendingRequestHandle.equals(prh))
			throw new SecurityException("request handle tempered. Handle from loaded object not matching in memory handle");
		incomingRequestHandles.put(certReqId, pendingRequestHandle);
		return pendingRequestData;
	}
	public IncomingInitializationRequestData loadRequest(BigInteger certRequestId){
		if(!incomingRequestHandles.containsKey(certRequestId)) return null;
		return loadPendingRequest(incomingRequestHandles.get(certRequestId));
	}
	
	public Collection<IncomingRequestHandle> listHandles(){
		return incomingRequestHandles.values();
	}
}
