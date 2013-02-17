package org.adorsys.plh.pkix.core.cmp;

import java.util.Date;

import org.bouncycastle.asn1.cmp.PKIMessage;

public class PendingRequestHolder implements Comparable<PendingRequestHolder>{

	private PKIMessage pkiMessage;
	private PKIMessage pollRepMessage;
	
	private PKIMessage pollReqMessage;

    private Date nextPoll;

    public PKIMessage getPkiMessage() {
		return pkiMessage;
	}
	public void setPkiMessage(PKIMessage pkiMessage) {
		this.pkiMessage = pkiMessage;
	}

	public Date getNextPoll() {
		return nextPoll;
	}
	public void setNextPoll(Date nextPoll) {
		this.nextPoll = nextPoll;
	}

	public PKIMessage getPollRepMessage() {
		return pollRepMessage;
	}
	public void setPollRepMessage(PKIMessage pollRepMessage) {
		this.pollRepMessage = pollRepMessage;
	}
	
	public PKIMessage getPollReqMessage() {
		return pollReqMessage;
	}
	public void setPollReqMessage(PKIMessage pollReqMessage) {
		this.pollReqMessage = pollReqMessage;
	}
	
	@Override
	public int compareTo(PendingRequestHolder o) {
		if(o==null || o.nextPoll==null){
			if(nextPoll==null) return 0;
			
			return 1;
		}
		if(nextPoll==null) return -1;
		
		return nextPoll.compareTo(o.nextPoll);
	}
}
