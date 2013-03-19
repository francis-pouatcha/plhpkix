package org.adorsys.plh.pkix.core.utils.action;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1MessageBundle;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1MessageBundles;
import org.adorsys.plh.pkix.core.utils.asn1.ASN1ProcessingResult;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.i18n.ErrorBundle;

public class ProcessingResults<T> implements ErrorsAndNotificationsHolder{

	private ASN1OctetString transactionID;
	private Date created;
	
	private final List<ErrorBundle> errors = new ArrayList<ErrorBundle>();
	private final List<ErrorBundle> notifications = new ArrayList<ErrorBundle>();

	private T returnValue;
	private boolean returnValueSet = false;
	
	public ProcessingResults() {
		created = new Date();
		transactionID = new DEROctetString(UUIDUtils.newUUIDAsBytes());
	}
	public ProcessingResults(ASN1OctetString transactionID) {
		created = new Date();
		this.transactionID = transactionID;
	}
	public ProcessingResults(Date created, ASN1OctetString transactionID) {
		this.created = created;
		this.transactionID = transactionID;
	}

	public ProcessingResults(ProcessingResults<T> clone) {
		created = clone.getCreated();
		transactionID = clone.getTransactionID();
		errors.addAll(clone.getErrors());
		notifications.addAll(clone.getNotifications());
		if(clone.hasReturnValue()){
			setReturnValue(clone.getReturnValue());
		}
	}

	public Date getCreated() {
		return created;
	}

	public ASN1OctetString getTransactionID() {
		return transactionID;
	}

	public ProcessingResults(ErrorsAndNotificationsHolder clone) {
		errors.addAll(clone.getErrors());
		notifications.addAll(clone.getNotifications());
	}
	
	@Override
	public void addError(ErrorBundle errorBundle){
		errors.add(errorBundle);
	}

	@Override
	public void addNotification(ErrorBundle errorBundle){
		notifications.add(errorBundle);
	}

	@Override
	public List<ErrorBundle> getErrors() {
		return Collections.unmodifiableList(errors);
	}

	@Override
	public List<ErrorBundle> getNotifications() {
		return Collections.unmodifiableList(notifications);
	}
	
	@Override
	public boolean hasError(){
		return !errors.isEmpty();
	}
	
	@Override
	public boolean hasNotification(){
		return !notifications.isEmpty();
	}
	
	@Override
	public void addErrors(List<ErrorBundle> in){
		errors.addAll(in);
	}

	@Override
	public void addNotifications(List<ErrorBundle> in){
		notifications.addAll(in);
	}

	public T getReturnValue() {
		return returnValue;
	}

	public void setReturnValue(T returnValue) {
		returnValueSet=true;
		this.returnValue = returnValue;
	}
	
	public boolean hasReturnValue(){
		return returnValueSet;
	}
	
	public ASN1ProcessingResult getASN1ProcessingResult(){
		if(!hasError() && !hasNotification()) return null;
		ASN1ProcessingResult processingResult = new ASN1ProcessingResult(transactionID, new DERGeneralizedTime(created));
		if(hasError()){
			List<ASN1MessageBundle> asnErrorBundle = new ArrayList<ASN1MessageBundle>(errors.size());
			for (ErrorBundle errorBundle : errors) {
				asnErrorBundle.add(new ASN1MessageBundle(errorBundle, Locale.getDefault()));
			}
			processingResult.setErrors(new ASN1MessageBundles(asnErrorBundle.toArray(new ASN1MessageBundle[asnErrorBundle.size()])));
		}
		if(hasNotification()){
			List<ASN1MessageBundle> asnNotifBundle = new ArrayList<ASN1MessageBundle>(notifications.size());
			for (ErrorBundle errorBundle : notifications) {
				asnNotifBundle.add(new ASN1MessageBundle(errorBundle, Locale.getDefault()));
			}
			processingResult.setNotifications(new ASN1MessageBundles(asnNotifBundle.toArray(new ASN1MessageBundle[asnNotifBundle.size()])));
		}
		return processingResult;
	}
}
