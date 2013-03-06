package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

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
import org.bouncycastle.asn1.DERIA5String;

/**
 * Manages outgoing certification requests. Before the request is sent out
 * it is stored here so if the is any exception, it is documented in the 
 * request.
 * 
 * @author francis
 *
 */
public class OutgoingCertificationRequests {
	
	private static final String DIRRELATIVEPATH = "outgoing_certification_requests";
	private final FileWrapper rootDir;
	
	private Map<BigInteger, OutgoingCertificationRequestHandle> outgoingRequestHandles = new HashMap<BigInteger, OutgoingCertificationRequestHandle>();
	private Map<BigInteger, OutgoingCertificationRequestData> outgoingRequestCache = new HashMap<BigInteger, OutgoingCertificationRequestData>();
	
	
	public OutgoingCertificationRequests(FileWrapper accountDir) {
		this.rootDir = accountDir.newChild(DIRRELATIVEPATH);
	}

	public void storeCertificationRequest(BigInteger certReqId, OutgoingCertificationRequestData requestData){
		OutgoingCertificationRequest certificationRequest = requestData.getOutgoingCertificationRequest();
		DERGeneralizedTime sending = certificationRequest.getSending();
		Date sdg = null;
		if(sending!=null)
			try {
				sdg = sending.getDate();
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		DERGeneralizedTime sent = certificationRequest.getSent();
		Date st=null;
		if(sent!=null)
			try {
				st = sent.getDate();
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		if(outgoingRequestHandles.containsKey(certReqId)){
			deleteRequest(certReqId);
		}
		DERIA5String status = certificationRequest.getStatus();
		String stus = status==null?null:status.getString();
		OutgoingCertificationRequestHandle  requestHandle = new OutgoingCertificationRequestHandle(certReqId, sdg,st,stus);
		FileWrapper fileWrapper = rootDir.newChild(requestHandle.getFileName());
		OutputStream outputStream = fileWrapper.newOutputStream();
		requestData.writeTo(outputStream);
		IOUtils.closeQuietly(outputStream);
		outgoingRequestCache.put(certReqId, requestData);
		outgoingRequestHandles.put(certReqId, requestHandle);
	}	
	
	public void markSent(BigInteger certReqId, String status){
		OutgoingCertificationRequestData requestData = loadRequest(certReqId);
		if(requestData==null) return;
		OutgoingCertificationRequest certificationRequest = requestData.getOutgoingCertificationRequest();
		DERIA5String statusDERIA5String = certificationRequest.getStatus();
		if(status!=null)
			statusDERIA5String = new DERIA5String(status);

		certificationRequest = new OutgoingCertificationRequest(certificationRequest.getCertReqId(), 
				certificationRequest.getPkiMessage(), certificationRequest.getSending(), 
				new DERGeneralizedTime(new Date()), statusDERIA5String);
		
		requestData = new OutgoingCertificationRequestData(certificationRequest);
		storeCertificationRequest(certReqId, requestData);
	}

	public void deleteRequest(BigInteger certReqId){
		if(!outgoingRequestHandles.containsKey(certReqId)) return;		
		outgoingRequestHandles.remove(certReqId);
		outgoingRequestCache.remove(certReqId);
			
		OutgoingCertificationRequestHandle requestHandle = outgoingRequestHandles.remove(certReqId);
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
		OutgoingCertificationRequestHandle pendingRequestHandle = new OutgoingCertificationRequestHandle(fileName);
		outgoingRequestHandles.put(pendingRequestHandle.getCertReqId(), pendingRequestHandle);
	}

	public OutgoingCertificationRequestData loadPendingRequest(OutgoingCertificationRequestHandle pendingRequestHandle){		
		BigInteger certReqId = pendingRequestHandle.getCertReqId();
		if(outgoingRequestCache.containsKey(certReqId))
			return outgoingRequestCache.get(certReqId);
		
		FileWrapper fileWrapper = rootDir.newChild(pendingRequestHandle.getFileName());
		if(!fileWrapper.exists()){
			throw new IllegalArgumentException("Missing underlying file");
		}

		InputStream newInputStream = fileWrapper.newInputStream();
		OutgoingCertificationRequestData pendingRequestData = new OutgoingCertificationRequestData();
		pendingRequestData.readFrom(newInputStream);
		IOUtils.closeQuietly(newInputStream);

		OutgoingCertificationRequest pendingRequest = pendingRequestData.getOutgoingCertificationRequest();
		OutgoingCertificationRequestHandle prh = new OutgoingCertificationRequestHandle(pendingRequest);
		if(!pendingRequestHandle.equals(prh))
			throw new SecurityException("request handle tempered. Handle from loaded object not matching in memory handle");
		outgoingRequestHandles.put(certReqId, pendingRequestHandle);
		return pendingRequestData;
	}
	public OutgoingCertificationRequestData loadRequest(BigInteger certRequestId){
		if(!outgoingRequestHandles.containsKey(certRequestId)) return null;
		return loadPendingRequest(outgoingRequestHandles.get(certRequestId));
	}
	
	public Collection<OutgoingCertificationRequestHandle> listHandles(){
		return outgoingRequestHandles.values();
	}
}
