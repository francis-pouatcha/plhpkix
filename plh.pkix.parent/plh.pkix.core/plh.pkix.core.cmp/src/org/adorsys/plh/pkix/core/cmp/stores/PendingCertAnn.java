package org.adorsys.plh.pkix.core.cmp.stores;

import java.util.LinkedList;

import org.bouncycastle.cert.X509CertificateHolder;

public class PendingCertAnn {
	
	private LinkedList<X509CertificateHolder> x509CertificateHolders = new LinkedList<X509CertificateHolder>();
	
	public X509CertificateHolder getNext(){
		return x509CertificateHolders.poll();
	}	
	public void add(X509CertificateHolder certificateHolder){
		x509CertificateHolders.add(certificateHolder);
	}
}
