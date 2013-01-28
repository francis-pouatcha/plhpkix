package org.adorys.plh.pkix.core.cmp.certann;

import java.security.Provider;
import java.util.Date;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateAnnouncementBuilder {

	private X509CertificateHolder subjectCertificate;
	private PrivateKeyHolder privateKeyHolder;
	private X500Name subjectName;
	
	public CertificateAnnouncementHolder build0(){
		try {
			validate();
			Provider provider = PlhCMPSystem.getProvider();
	        GeneralName subject = new GeneralName(subjectName);
	        GeneralName server = new GeneralName(PlhCMPSystem.getServerName());
	
	        ContentSigner subjectSigner;
			try {
				subjectSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption")
					.setProvider(provider).build(privateKeyHolder.getPrivateKey(KeyIdUtils.getSubjectKeyIdentifierAsOctetString(subjectCertificate)));
			} catch (OperatorCreationException e) {
				throw new IllegalStateException(e);
			}
			
	        byte[] subjectKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(subjectCertificate);
	        CMPCertificate cmpCertificate = new CMPCertificate(subjectCertificate.toASN1Structure());
	
	        ProtectedPKIMessage mainMessage;
			try {
				mainMessage = new ProtectedPKIMessageBuilder(subject, server)
				    .setBody(new PKIBody(PKIBody.TYPE_CERT_ANN, cmpCertificate))
				    .addCMPCertificate(subjectCertificate)
				    .setMessageTime(new Date())
				    .setSenderKID(subjectKeyId)
				    .setSenderNonce(UUIDUtils.newUUIDAsBytes())
				    .setTransactionID(UUIDUtils.newUUIDAsBytes())
				    .build(subjectSigner);
			} catch (CMPException e) {
				throw new IllegalStateException(e);
			}
	        
	        PKIMessage pkiMessage = mainMessage.toASN1Structure();
			return new CertificateAnnouncementHolder(pkiMessage);
		} finally {
			end();
		}
	}

	public CertificateAnnouncementBuilder withSubjectCertificate(X509CertificateHolder subjectCertificate) {
		this.subjectCertificate = subjectCertificate;
		return this;
	}

	public CertificateAnnouncementBuilder withSubjectName(X500Name subjectName) {
		this.subjectName = subjectName;
		return this;
	}

	public CertificateAnnouncementBuilder withPrivateKeyHolder(PrivateKeyHolder privateKeyHolder) {
		this.privateKeyHolder = privateKeyHolder;
		return this;
	}
	
	private void validate(){
		assert subjectCertificate!=null: "Field subjectCertificate can not be null";
		assert subjectName!=null: "Field subjectName can not be null";
		assert privateKeyHolder!=null: "Field privateKeyHolder can not be null";
	}
	
	private void end(){
		subjectCertificate=null;
		subjectName=null;
		privateKeyHolder=null;
	}
}
