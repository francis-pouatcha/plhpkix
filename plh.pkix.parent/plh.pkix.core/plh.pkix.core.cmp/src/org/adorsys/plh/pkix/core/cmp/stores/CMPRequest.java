package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;

import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Action;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1Actions;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResults;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingStatus;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class CMPRequest extends ASN1Object {

	// Mandatory
	private ASN1OctetString transactionID;
	private DERGeneralizedTime created;
	private ASN1ProcessingStatus status;
	
	// Optional
	private ASN1Actions nextActions;

	private ASN1Actions previousActions;
	
	private PKIMessage pkiMessage;
	private PKIMessage responseMessage;

	private PKIMessage pollRepMessage;
	private PKIMessage pollReqMessage;
	
	private ASN1ProcessingResults processingResults;

	private DERGeneralizedTime disposed;
	

    private CMPRequest(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
		Enumeration en = seq.getObjects();

        transactionID = ASN1OctetString.getInstance(en.nextElement());
        created= DERGeneralizedTime.getInstance(en.nextElement());
        status = new ASN1ProcessingStatus(ASN1ProcessingStatus.getInstance(en.nextElement()));
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            switch (tObj.getTagNo())
            {
            case 0:
                nextActions = ASN1Actions.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 1:
            	previousActions = ASN1Actions.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 2:
                pkiMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 3:
            	responseMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 4:
            	pollReqMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 5:
            	pollRepMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 6:
            	processingResults = ASN1ProcessingResults.getInstance(ASN1Sequence.getInstance(tObj, true));
                break;
            case 7:
                disposed = DERGeneralizedTime.getInstance(tObj, true);
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static CMPRequest getInstance(Object o)
    {
        if (o instanceof CMPRequest)
        {
            return (CMPRequest)o;
        }

        if (o != null)
        {
            return new CMPRequest(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CMPRequest(ASN1OctetString transactionID,
    		DERGeneralizedTime created)
    {
    	this.transactionID = transactionID;
        this.created = created;
        this.status = new ASN1ProcessingStatus(ASN1ProcessingStatus.unknown);
    }

    public CMPRequest()
    {
    	this.transactionID = UUIDUtils.newUUIDasASN1OctetString();
        this.created = new DERGeneralizedTime(new Date());
        this.status = new ASN1ProcessingStatus(ASN1ProcessingStatus.unknown);
    }

	/**
     * <pre>
     * PendingRequestData ::= SEQUENCE {
     * 					transactionID			ASN1OctetString
     *                  created        			DERGeneralizedTime,
     *                  status  				DERIA5String,
     *                  nextActions 		[0] ASN1Actions OPTIONAL,
     *                  previousActions 	[1] ASN1Actions OPTIONAL,
     *                  pkiMessage 			[2] PKIMessage OPTIONAL,
     *                  responseMessage 	[3] PKIMessage OPTIONAL,
     *                  pollReqMessage  	[4] PKIMessage OPTIONAL
     *                  pollRepMessage  	[5] PKIMessage OPTIONAL,
     *                  processingResults 	[6] ASN1ProcessingResults OPTIONAL,
     *                  disposed   			[7] DERGeneralizedTime OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
	@Override
	public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(transactionID);
        v.add(created);
        v.add(status);

        addOptional(v, 0, nextActions);
        addOptional(v, 1, previousActions);
        addOptional(v, 2, pkiMessage);
        addOptional(v, 3, responseMessage);
        addOptional(v, 4, pollReqMessage);
        addOptional(v, 5, pollRepMessage);
        addOptional(v, 6, processingResults);
        addOptional(v, 7, disposed);

        return new DERSequence(v);
	}

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

	public ASN1ProcessingStatus getStatus() {
		return status;
	}
	
	public void addStatus(int s){
		if(hasStatus(ASN1ProcessingStatus.unknown)){
			status = new ASN1ProcessingStatus(s);
		} else {
			status = new ASN1ProcessingStatus(status.intValue() | s);
		}
	}
	
	public boolean hasStatus(int s){
		int intValue = status.intValue();
		return (intValue & s) == s;
	}

	public ASN1Actions getNextActions() {
		return nextActions;
	}

	public void setNextActions(ASN1Actions nextActions) {
		this.nextActions = nextActions;
	}

	public ASN1Actions getPreviousActions() {
		return previousActions;
	}

	public void setPreviousActions(ASN1Actions previousActions) {
		this.previousActions = previousActions;
	}

	public PKIMessage getPkiMessage() {
		return pkiMessage;
	}

	public void setPkiMessage(PKIMessage pkiMessage) {
		this.pkiMessage = pkiMessage;
	}

	public PKIMessage getResponseMessage() {
		return responseMessage;
	}

	public void setResponseMessage(PKIMessage responseMessage) {
		this.responseMessage = responseMessage;
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

	public ASN1ProcessingResults getProcessingResults() {
		return processingResults;
	}

	public void setProcessingResults(ASN1ProcessingResults processingResults) {
		this.processingResults = processingResults;
	}

	public DERGeneralizedTime getDisposed() {
		return disposed;
	}

	public void setDisposed(DERGeneralizedTime disposed) {
		this.disposed = disposed;
	}

	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public DERGeneralizedTime getCreated() {
		return created;
	}
	
	public ASN1ProcessingResult getLastProcessingResult(){
		if(processingResults!=null){
			ASN1ProcessingResult[] resultArray = processingResults.toResultArray();
			if(resultArray.length>1) return resultArray[0];
		}
		return null;
	}
	
	public boolean hasError(){
		ASN1ProcessingResult lastProcessingResult = getLastProcessingResult();
		if(lastProcessingResult==null) return false;
		return lastProcessingResult.getErrors()!=null;
	}
	
	public void addProcessingResult(ASN1ProcessingResult result){
		if(processingResults==null){
			processingResults = new ASN1ProcessingResults(result);
		} else {
			ASN1ProcessingResult[] resultArray = processingResults.toResultArray();
			ArrayList<ASN1ProcessingResult> list = new ArrayList<ASN1ProcessingResult>(resultArray.length+1);
			list.add(result);
			for (ASN1ProcessingResult asn1ProcessingResult : resultArray) {
				list.add(asn1ProcessingResult);
			}
			processingResults = new ASN1ProcessingResults(list.toArray(new ASN1ProcessingResult[list.size()]));
		}
	}
	
	public void pushNextAction(ASN1Action action){
		if(nextActions==null){
			nextActions = new ASN1Actions(action);
		} else {
			ASN1Action[] actionArray = nextActions.toActionArray();
			ArrayList<ASN1Action> list = new ArrayList<ASN1Action>(actionArray.length+1);
			list.add(action);
			for (ASN1Action asn1Action : actionArray) {
				list.add(asn1Action);
			}
			nextActions = new ASN1Actions(list.toArray(new ASN1Action[list.size()]));
		}
	}
	public ASN1Action popNextAction(){
		if(nextActions==null) return null;

		ASN1Action nextAction = null;
		ASN1Action[] actionArray = nextActions.toActionArray();
		if(actionArray.length>1)nextAction = actionArray[0];
		if(actionArray.length<2){
			nextActions=null;
		} else {
			ASN1Action[] newActionArray = Arrays.copyOfRange(actionArray, 1, actionArray.length);
			nextActions = new ASN1Actions(newActionArray);
		}
		return nextAction;
	}

	public void pushPreviousAction(ASN1Action action){
		if(previousActions==null){
			previousActions = new ASN1Actions(action);
		} else {
			ASN1Action[] actionArray = previousActions.toActionArray();
			ArrayList<ASN1Action> list = new ArrayList<ASN1Action>(actionArray.length+1);
			list.add(action);
			for (ASN1Action asn1Action : actionArray) {
				list.add(asn1Action);
			}
			previousActions = new ASN1Actions(list.toArray(new ASN1Action[list.size()]));
		}
	}
	public ASN1Action popPreviousAction(){
		if(previousActions==null) return null;
		ASN1Action nextAction = null;
		ASN1Action[] actionArray = previousActions.toActionArray();
		if(actionArray.length>1)nextAction = actionArray[0];
		if(actionArray.length<2){
			previousActions=null;
		} else {
			ASN1Action[] newActionArray = Arrays.copyOfRange(actionArray, 1, actionArray.length);
			previousActions = new ASN1Actions(newActionArray);
		}
		return nextAction;
	}

	public void disposeCurentAction(){
		if(nextActions==null) return;
		ASN1Action action = popNextAction();
		if(action!=null){
			action.setDisposed(new DERGeneralizedTime(new Date()));
			pushPreviousAction(action);
		}
	}
}
