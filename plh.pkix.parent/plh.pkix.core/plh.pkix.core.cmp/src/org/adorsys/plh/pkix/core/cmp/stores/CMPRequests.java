package org.adorsys.plh.pkix.core.cmp.stores;

import java.io.InputStream;
import java.io.OutputStream;

import org.adorsys.plh.pkix.core.utils.action.ASN1StreamUtils;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1OctetString;

/**
 * Manages CMP requests.
 * 
 * @author francis
 *
 */
public abstract class CMPRequests {
	
	private final FileWrapper requestDir;

	public abstract String getRequestDir();
	
	public CMPRequests(FileWrapper accountDir) {
		this.requestDir = accountDir.newChild(getRequestDir());
	}
	
	public String storeRequest(CMPRequest request){
		String fileName = makeFileName(request);
		String existingFileName = getExistingOutgoingRequestFileName(request.getTransactionID());
		if(existingFileName!=null && !existingFileName.equals(fileName))
			throw new IllegalStateException("Outgoing request with trasaction id exist.");
		
		FileWrapper fileWrapper = requestDir.newChild(fileName);
		OutputStream outputStream = fileWrapper.newOutputStream();
		ASN1StreamUtils.writeTo(request, outputStream);
		IOUtils.closeQuietly(outputStream);
		return fileName;
	}	

	public void deleteRequest(CMPRequest request){
		String fileName = makeFileName(request);
		FileWrapper fileWrapper = requestDir.newChild(fileName);
		if(fileWrapper.exists()) fileWrapper.delete();
	}

	public CMPRequest loadRequest(ASN1OctetString transactionID){
		String[] children = requestDir.list();
		String fileName = CMPRequestFileNameHelper.find(children, transactionID);
		if(fileName==null) return null;
		FileWrapper fileWrapper = requestDir.newChild(fileName);
		InputStream inputStream = fileWrapper.newInputStream();
		CMPRequest cmpRequest = CMPRequest.getInstance(ASN1StreamUtils.readFrom(inputStream));
		IOUtils.closeQuietly(inputStream);
		return cmpRequest;

	}

	private String makeFileName(CMPRequest outgoingRequest){
		return CMPRequestFileNameHelper.makeFileName(outgoingRequest.getTransactionID(),outgoingRequest.getCreated());
	}

	/**
	 * Check if the outgoing request with this transaction id exists.
	 * @param transactionID
	 * @return
	 */
	private String getExistingOutgoingRequestFileName(ASN1OctetString transactionID){
		String[] children = requestDir.list();
		if(!requestDir.exists()) return null;
		return CMPRequestFileNameHelper.find(children, transactionID);
	}
}
