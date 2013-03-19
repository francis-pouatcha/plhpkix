package org.adorsys.plh.pkix.core.utils.jca;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.adorsys.plh.pkix.core.utils.BuilderChecker;
import org.adorsys.plh.pkix.core.utils.KeyUsageUtils;
import org.adorsys.plh.pkix.core.utils.UUIDUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.exception.PlhUncheckedValidationException;
import org.adorsys.plh.pkix.core.utils.store.PlhPkixCoreMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.operator.ContentSigner;

/**
 * Build a certificate based on information passed to this object.
 * 
 * The subjectSampleCertificate can be used as a model. The ca can create some of the fields manually so
 * so modifying suggestions provided by the sample certificate.
 * 
 * The object shall not be reused. After the build method is called, this object is not reusable.
 * 
 * 
 * @author francis
 *
 */
public class X509CertificateBuilder {

	private boolean ca;

	private X500Name subjectDN;
	
	private boolean subjectOnlyInAlternativeName;

	private PublicKey subjectPublicKey;

	private Date notBefore;

	private Date notAfter;

	private X509CertificateHolder subjectSampleCertificate;

	private X509CertificateHolder issuerCertificate;

	private int keyUsage=-1;
	private boolean keyUsageSet = false;

	private GeneralNames subjectAltNames;

	private AuthorityInformationAccess authorityInformationAccess;

	private final BuilderChecker checker = new BuilderChecker(X509CertificateBuilder.class);
	public X509CertificateHolder build(PrivateKey issuerPrivatekey) {
		checker.checkDirty();
		
		if(subjectSampleCertificate!=null){
			if(subjectPublicKey==null) subjectPublicKey=V3CertificateUtils.extractPublicKey(subjectSampleCertificate);
			if(subjectDN==null) subjectDN=subjectSampleCertificate.getSubject();
			if(notBefore==null) notBefore=subjectSampleCertificate.getNotBefore();
			if(notAfter==null) notAfter=subjectSampleCertificate.getNotAfter();
			
			if(!keyUsageSet)copyKeyUsage(subjectSampleCertificate);
			
			if(subjectAltNames==null){
				Extension extension = subjectSampleCertificate.getExtension(X509Extension.subjectAlternativeName);
				if(extension!=null) subjectAltNames = GeneralNames.getInstance(extension.getParsedValue());
			}
			
			if(authorityInformationAccess==null){
				Extension extension = subjectSampleCertificate.getExtension(X509Extension.authorityInfoAccess);
				if(extension!=null) authorityInformationAccess = AuthorityInformationAccess.getInstance(extension.getParsedValue());
			}
		}
		
		List<String> errorKeys = new ArrayList<String>();
		if(subjectPublicKey==null) errorKeys.add(PlhPkixCoreMessages.X509CertificateBuilder_missing_subject_publicKey);
		// to set subject to empty, set subjectOnlyInAltName to true. See rfc 5280 then subject alt name must be set
		if(subjectDN==null) errorKeys.add(PlhPkixCoreMessages.X509CertificateBuilder_missing_subject_DN);
		if(notBefore==null) errorKeys.add(PlhPkixCoreMessages.X509CertificateBuilder_missing_validity_date_notBefore);
		if(notAfter==null) errorKeys.add(PlhPkixCoreMessages.X509CertificateBuilder_missing_validity_date_notAfter);
		if(!errorKeys.isEmpty()){
			List<ErrorBundle> errors = new ArrayList<ErrorBundle>();
            ErrorBundle haedMsg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
            		PlhPkixCoreMessages.X509CertificateBuilder_missing_inputs);
            errors.add(haedMsg);
			for (String errorKey : errorKeys) {
	            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),errorKey);
	            errors.add(msg);
			}
            throw new PlhUncheckedValidationException(errors);
		}

		X500Name issuerDN = null;
		BasicConstraints basicConstraints = null;
		if(issuerCertificate==null){
			issuerDN = subjectDN;
			if(ca){
				// self signed ca certificate
				basicConstraints = new BasicConstraints(true);
				subjectOnlyInAlternativeName = false;// in ca case, subject must subject must be set
			} else {
				basicConstraints = new BasicConstraints(false);
			}
		} else {			
			// check is issuerCertificate is ca certificate
			Extension basicConstraintsExtension = issuerCertificate.getExtension(X509Extension.basicConstraints);
			BasicConstraints issuerBasicConstraints = BasicConstraints.getInstance(basicConstraintsExtension.getParsedValue());
			if(!issuerBasicConstraints.isCA())
				errorKeys.add(PlhPkixCoreMessages.X509CertificateBuilder_issuerCert_notCaCert);
			
			if(!KeyUsageUtils.hasAllKeyUsage(issuerCertificate, KeyUsage.keyCertSign))
				errorKeys.add(PlhPkixCoreMessages.X509CertificateBuilder_issuerCert_notForCertSign);

			if(!errorKeys.isEmpty()){
				List<ErrorBundle> errors = new ArrayList<ErrorBundle>();
	            ErrorBundle haedMsg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),
	            		PlhPkixCoreMessages.X509CertificateBuilder_issuerCert_invalid);
	            errors.add(haedMsg);
				for (String errorKey : errorKeys) {
		            ErrorBundle msg = new ErrorBundle(PlhPkixCoreMessages.class.getName(),errorKey);
		            errors.add(msg);
				}
				
	            throw new PlhUncheckedValidationException(errors);
			}

			// prepare inputs
			issuerDN = issuerCertificate.getSubject();

			if(ca){// ca signing another ca certificate
				subjectOnlyInAlternativeName = false;// in ca case, subject must subject must be set
				// ca certificate must carry a subject
				BigInteger pathLenConstraint = issuerBasicConstraints.getPathLenConstraint();
				if(pathLenConstraint==null){
					pathLenConstraint = BigInteger.ONE;
				} else {
					pathLenConstraint = pathLenConstraint.add(BigInteger.ONE);
				}
				basicConstraints = new BasicConstraints(pathLenConstraint.intValue());
				withKeyUsage(KeyUsage.keyCertSign);
			} else {// ca issuing a simple certificate
				basicConstraints = new BasicConstraints(false);
			}
		}

		BigInteger serial = UUIDUtils.toBigInteger(UUID.randomUUID());
		X509v3CertificateBuilder v3CertGen = null;
		if(subjectOnlyInAlternativeName && subjectAltNames!=null){
			v3CertGen = new JcaX509v3CertificateBuilder(issuerDN, serial, notBefore, notAfter, new X500Name("cn="),subjectPublicKey);
		} else {
			v3CertGen = new JcaX509v3CertificateBuilder(issuerDN, serial, notBefore, notAfter, subjectDN,subjectPublicKey);
		}
		JcaX509ExtensionUtils extUtils = V3CertificateUtils.getJcaX509ExtensionUtils();

		try {
			v3CertGen.addExtension(X509Extension.basicConstraints,true, basicConstraints);
			
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier,false, 
					extUtils.createSubjectKeyIdentifier(subjectPublicKey));
			
			if(issuerCertificate==null){
				v3CertGen.addExtension(X509Extension.authorityKeyIdentifier,false,
						extUtils.createAuthorityKeyIdentifier(subjectPublicKey));
			} else {
				v3CertGen.addExtension(X509Extension.authorityKeyIdentifier,false,
						extUtils.createAuthorityKeyIdentifier(issuerCertificate));
			}
			
			if(keyUsageSet){
				v3CertGen.addExtension(X509Extension.keyUsage,
						true, new KeyUsage(this.keyUsage));
			}

			// complex rules for subject alternative name. See rfc5280
			if(subjectAltNames!=null){
				if(subjectOnlyInAlternativeName){
					v3CertGen.addExtension(X509Extension.subjectAlternativeName, true, subjectAltNames);
				} else {
					v3CertGen.addExtension(X509Extension.subjectAlternativeName, false, subjectAltNames);
				}
			}
			
			if(authorityInformationAccess!=null)
				v3CertGen.addExtension(X509Extension.authorityInfoAccess, false, authorityInformationAccess);
				
		} catch (CertIOException e) {
			throw new IllegalStateException(e);
		}

		ContentSigner signer = V3CertificateUtils.getContentSigner(issuerPrivatekey,"SHA1WithRSA");

		return v3CertGen.build(signer);

	}
	
	private void copyKeyUsage(X509CertificateHolder issuerCertificate) {
		int ku = KeyUsageUtils.getKeyUsage(issuerCertificate);
		if(ku!=-1)withKeyUsage(ku);
	}

	public X509CertificateBuilder withCa(boolean ca) {
		this.ca = ca;
		return this;
	}

	public X509CertificateBuilder withSubjectDN(X500Name subjectDN) {
		this.subjectDN = subjectDN;
		return this;
	}

	public X509CertificateBuilder withSubjectPublicKey(PublicKey subjectPublicKey) {
		this.subjectPublicKey = subjectPublicKey;
		return this;
	}

	public X509CertificateBuilder withNotBefore(Date notBefore) {
		this.notBefore = notBefore;
		return this;
	}

	public X509CertificateBuilder withNotAfter(Date notAfter) {
		this.notAfter = notAfter;
		return this;
	}

	public X509CertificateBuilder withSubjectSampleCertificate(
			X509CertificateHolder subjectSampleCertificate) {
		this.subjectSampleCertificate = subjectSampleCertificate;
		return this;
	}

	public X509CertificateBuilder withIssuerCertificate(
			X509CertificateHolder issuerCertificate) {
		this.issuerCertificate = issuerCertificate;
		return this;
	}

	public X509CertificateBuilder withKeyUsage(int keyUsage) {
		if(keyUsageSet){
			this.keyUsage=this.keyUsage|keyUsage;
		} else {
			this.keyUsage=keyUsage;
			keyUsageSet=true;
		}
		return this;
	}

	public X509CertificateBuilder withSubjectAltNames(GeneralNames subjectAltNames) {
		if(this.subjectAltNames==null){
			this.subjectAltNames = new GeneralNames(subjectAltNames.getNames());
		} else {
			ArrayList<GeneralName> nameList = new ArrayList<GeneralName>();
			GeneralName[] names1 = this.subjectAltNames.getNames();
			for (GeneralName generalName : names1) {
				if(!nameList.contains(generalName))
					nameList.add(generalName);
			}
			GeneralName[] names2 = subjectAltNames.getNames();
			for (GeneralName generalName : names2) {
				if(!nameList.contains(generalName))
					nameList.add(generalName);
			}
			GeneralName[] names = nameList.toArray(new GeneralName[nameList.size()]);
			this.subjectAltNames = new GeneralNames(names);
		}
		return this;
	}

	public X509CertificateBuilder withSubjectAltName(GeneralName subjectAltName) {
		if(this.subjectAltNames==null){
			this.subjectAltNames = new GeneralNames(subjectAltName);
		} else {
			ArrayList<GeneralName> nameList = new ArrayList<GeneralName>();
			GeneralName[] names1 = this.subjectAltNames.getNames();
			for (GeneralName generalName : names1) {
				if(!nameList.contains(generalName))
					nameList.add(generalName);
			}
			nameList.add(subjectAltName);
			GeneralName[] names = nameList.toArray(new GeneralName[nameList.size()]);
			this.subjectAltNames = new GeneralNames(names);
		}
		return this;
	}
	
	public X509CertificateBuilder withAuthorityInformationAccess(
			AuthorityInformationAccess authorityInformationAccess) {
		this.authorityInformationAccess = authorityInformationAccess;
		return this;
	}

	public X509CertificateBuilder withSubjectOnlyInAlternativeName(boolean subjectOnlyInAlternativeName) {
		this.subjectOnlyInAlternativeName = subjectOnlyInAlternativeName;
		return this;
	}
	
	
}
