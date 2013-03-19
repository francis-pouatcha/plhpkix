package org.adorsys.plh.pkix.core.cmp.initrequest.receiver;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequest;
import org.adorsys.plh.pkix.core.cmp.stores.IncomingRequestHandle;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1OctetString;

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
	
	private Map<String, IncomingRequestHandle> incomingRequestHandles = new HashMap<String, IncomingRequestHandle>();
	private Map<String, IncomingInitializationRequestData> incomingRequestCache = new HashMap<String, IncomingInitializationRequestData>();
	
	public IncomingInitializationRequests(FileWrapper accountDir) {
		this.rootDir = accountDir.newChild(DIRRELATIVEPATH);
	}

	public void storeRequest(IncomingInitializationRequestData requestData){
		IncomingRequest initializationRequest = requestData.getIncomingRequest();
		ASN1OctetString txid = initializationRequest.getPkiMessage().getHeader().getTransactionID();
		String transactionID = KeyIdUtils.hexEncode(txid);
		IncomingRequestHandle incomingRequestHandle = new IncomingRequestHandle(initializationRequest);
		if(incomingRequestHandles.containsKey(transactionID)){
			deleteRequest(transactionID);
		}
		FileWrapper fileWrapper = rootDir.newChild(incomingRequestHandle.getFileName());
		OutputStream outputStream = fileWrapper.newOutputStream();
		requestData.writeTo(outputStream);
		IOUtils.closeQuietly(outputStream);
		incomingRequestCache.put(transactionID, requestData);
		incomingRequestHandles.put(transactionID, incomingRequestHandle);
	}	

	public void deleteRequest(String transactionID){
		if(!incomingRequestHandles.containsKey(transactionID)) return;		
		IncomingRequestHandle requestHandle = incomingRequestHandles.remove(transactionID);
		incomingRequestCache.remove(transactionID);
			
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
		incomingRequestHandles.put(registrationRequestHandle.getTransactionID(), registrationRequestHandle);
	}

	public IncomingInitializationRequestData loadPendingRequest(IncomingRequestHandle pendingRequestHandle){		
		String transactionID = pendingRequestHandle.getTransactionID();
		if(incomingRequestCache.containsKey(transactionID))
			return incomingRequestCache.get(transactionID);
		
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
		incomingRequestHandles.put(transactionID, pendingRequestHandle);
		return pendingRequestData;
	}
	public IncomingInitializationRequestData loadRequest(String transactionID){
		if(!incomingRequestHandles.containsKey(transactionID)) return null;
		return loadPendingRequest(incomingRequestHandles.get(transactionID));
	}
	
	public Collection<IncomingRequestHandle> listHandles(){
		return incomingRequestHandles.values();
	}
}
