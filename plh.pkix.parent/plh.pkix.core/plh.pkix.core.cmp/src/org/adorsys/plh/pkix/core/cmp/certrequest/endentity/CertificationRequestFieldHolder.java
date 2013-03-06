package org.adorsys.plh.pkix.core.cmp.certrequest.endentity;

import java.util.Date;

import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Used to display a certification request and gather requestor feedback.
 * 
 * @author francis
 *
 */
public class CertificationRequestFieldHolder {

	private boolean ca;
	private boolean caSet;
	private X500Name subjectDN;
	private boolean subjectOnlyInAlternativeName;
	private SubjectPublicKeyInfo subjectPublicKeyInfo;
	private Date notBefore;
	private Date notAfter;
	private int keyUsage=-1;
	private boolean keyUsageSet = false;
	private GeneralNames subjectAltNames;
    private X500Name certAuthorityName;
	
	// the cert template. This is either the self signed certificate or
	// A certificate issued by another authority.
    private final X509CertificateHolder subjectPreCertificate;
    
    public CertificationRequestFieldHolder(X509CertificateHolder subjectPreCertificate){
    	this.subjectPreCertificate = subjectPreCertificate;
    	
		Extension basicConstraintsExtension = subjectPreCertificate.getExtension(X509Extension.basicConstraints);
		BasicConstraints basicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
		setCa(basicConstraints.isCA());

		subjectPublicKeyInfo=subjectPreCertificate.getSubjectPublicKeyInfo();
		subjectDN=subjectPreCertificate.getSubject();
		notBefore=subjectPreCertificate.getNotBefore();
		notAfter=subjectPreCertificate.getNotAfter();

		setKeyUsage(KeyUsageUtils.getKeyUsage(subjectPreCertificate));
		
		Extension extension = subjectPreCertificate.getExtension(X509Extension.subjectAlternativeName);
		if(extension!=null) subjectAltNames = GeneralNames.getInstance(extension.getParsedValue());
		
    }

	public boolean isCa() {
		return ca;
	}

	public void setCa(boolean ca) {
		this.ca = ca;
		this.caSet=true;
	}

	public boolean isCaSet() {
		return caSet;
	}

	public void setCaSet(boolean caSet) {
		this.caSet = caSet;
	}

	public X500Name getSubjectDN() {
		return subjectDN;
	}

	public void setSubjectDN(X500Name subjectDN) {
		this.subjectDN = subjectDN;
	}

	public boolean isSubjectOnlyInAlternativeName() {
		return subjectOnlyInAlternativeName;
	}

	public void setSubjectOnlyInAlternativeName(boolean subjectOnlyInAlternativeName) {
		this.subjectOnlyInAlternativeName = subjectOnlyInAlternativeName;
	}

	public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
		return subjectPublicKeyInfo;
	}

	public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
		this.subjectPublicKeyInfo = subjectPublicKeyInfo;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	public int getKeyUsage() {
		return keyUsage;
	}

	public void setKeyUsage(int keyUsage) {
		this.keyUsage = keyUsage;
		this.keyUsageSet=true;
	}

	public boolean isKeyUsageSet() {
		return keyUsageSet;
	}

	public void setKeyUsageSet(boolean keyUsageSet) {
		this.keyUsageSet = keyUsageSet;
	}

	public GeneralNames getSubjectAltNames() {
		return subjectAltNames;
	}

	public void setSubjectAltNames(GeneralNames subjectAltNames) {
		this.subjectAltNames = subjectAltNames;
	}

	public X500Name getCertAuthorityName() {
		return certAuthorityName;
	}

	public void setCertAuthorityName(X500Name certAuthorityName) {
		this.certAuthorityName = certAuthorityName;
	}

	public X509CertificateHolder getSubjectPreCertificate() {
		return subjectPreCertificate;
	}
}
