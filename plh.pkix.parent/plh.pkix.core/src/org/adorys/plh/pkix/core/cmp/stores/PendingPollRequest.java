package org.adorys.plh.pkix.core.cmp.stores;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.adorys.plh.pkix.core.cmp.PendingRequestHolder;
import org.bouncycastle.asn1.ASN1Integer;

public class PendingPollRequest {
	
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
