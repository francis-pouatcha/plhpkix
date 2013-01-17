package org.adorys.plh.pkix.core.cmp.stores;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.adorys.plh.pkix.core.cmp.PendingRequestHolder;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;

public class PendingPollRequest {
	
	private static final Map<X500Name, PendingPollRequest> instances = new HashMap<X500Name, PendingPollRequest>();

	public static PendingPollRequest getInstance(X500Name role){
		PendingPollRequest pendingCertRequests = instances.get(role);
		if(pendingCertRequests==null){
			pendingCertRequests = new PendingPollRequest();
			instances.put(role, pendingCertRequests);
		}
		return pendingCertRequests;
	}

	private Map<ASN1Integer, PendingRequestHolder> certRquests = new HashMap<ASN1Integer, PendingRequestHolder>();

	public PendingRequestHolder loadPollRequestHolder(ASN1Integer certRequestId){
		return certRquests.get(certRequestId);
	}
	
	public void storePollRequestHolder(ASN1Integer certReqId, PendingRequestHolder pollRequestHolder){
		certRquests.put(certReqId, pollRequestHolder);
	}
	
	public PendingRequestHolder removePollRequestHolder(ASN1Integer certRequestId){
		return certRquests.remove(certRequestId);
	}
	
	public List<PendingRequestHolder> loadPollRequests(){
		ArrayList<PendingRequestHolder> arrayList = new ArrayList<PendingRequestHolder>(certRquests.values());
		Collections.sort(arrayList);
		return arrayList;
	}
}
