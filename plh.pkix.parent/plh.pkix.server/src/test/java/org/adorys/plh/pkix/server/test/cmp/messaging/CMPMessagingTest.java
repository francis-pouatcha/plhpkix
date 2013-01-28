package org.adorys.plh.pkix.server.test.cmp.messaging;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.util.Date;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Response.Status;

import org.adorsys.plh.pkix.core.x500.X500NameHelper;
import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.OptionalValidityHolder;
import org.adorys.plh.pkix.core.cmp.utils.RequestVerifier;
import org.adorys.plh.pkix.core.cmp.utils.UUIDUtils;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
import org.adorys.plh.pkix.core.cmp.utils.X509CertificateHolderCollection;
import org.adorys.plh.pkix.server.cmp.utils.JaxRsActivator;
import org.adorys.plh.pkix.server.test.cmp.AbstractCMPMessagingServerTest;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.math.RandomUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
@RunAsClient
public class CMPMessagingTest {

    private static final String RESOURCE_PREFIX = JaxRsActivator.class.getAnnotation(ApplicationPath.class).value().substring(1);
	
	private static Provider provider = PlhCMPSystem.getProvider();
	
	private static final String SERVICE_NAME = "/messaging";

    @Deployment(testable=false)
    public static WebArchive createDeployment() {
    	return AbstractCMPMessagingServerTest.createDeployment();
    }

    @ArquillianResource
    URL deploymentUrl;

	@Test
	public void testInitializationRequest() throws OperatorCreationException, GeneralSecurityException, IOException, CertException, CMPException {
		// Generate a key pair for the new EndEntity
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", provider);
        kGen.initialize(512);
        KeyPair senderKeyPair = kGen.generateKeyPair();
        // Self sign the certificate
        X500Name francisX500Name = X500NameHelper.makeX500Name("Francis Pouatcha", "fpo@plhpkix.biz");
        X509CertificateHolder senderCert = V3CertificateUtils.makeSelfV3Certificate(
        		senderKeyPair, francisX500Name, new Date(), DateUtils.addYears(new Date(), 1), provider);
        byte[] sendeKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(senderCert);

        GeneralName sender = new GeneralName(francisX500Name);
        // first initialization request must be sent to the server
        X500Name recipientX500Name = PlhCMPSystem.getServerName();
        GeneralName recipient = new GeneralName(recipientX500Name);

        ContentSigner senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(senderKeyPair.getPrivate());
		
        byte[] transactionId = UUIDUtils.newUUIDAsBytes();
        
        // The initialization request must specify the SubjectPublicKeyInfo, The keyId and the validity
        // of each certificate requested.
		Date startDate = DateUtils.addYears(new Date(), -10);
		Date endDate = DateUtils.addYears(new Date(), 10);
		OptionalValidity optionalValidity = new OptionalValidityHolder(startDate, endDate).getOptionalValidity();
		CertTemplate certTemplate = new CertTemplateBuilder()
        	.setSubject(recipientX500Name)
        	.setIssuer(recipientX500Name)
        	.setValidity(optionalValidity).build();
		ASN1Integer certReqId = new ASN1Integer(RandomUtils.nextInt());
		Controls controls = null;
		CertRequest certRequest = new CertRequest(certReqId, certTemplate, controls);
		CertReqMsg certReqMsg = new CertReqMsg(certRequest, null, null);
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg[]{certReqMsg});
        ProtectedPKIMessage mainMessage = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages))
                                                  .addCMPCertificate(senderCert)
                                                  .setMessageTime(new Date())
                                                  .setSenderKID(sendeKeyId)
                                                  .setSenderNonce(UUIDUtils.newUUIDAsBytes())
                                                  .setTransactionID(transactionId)
                                                  .build(senderSigner);
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		String addr = deploymentUrl.toString()+ RESOURCE_PREFIX + SERVICE_NAME + "/req";

		HttpClient httpclient = new DefaultHttpClient();
		HttpEntity entity = new ByteArrayEntity(pkiMessage.getEncoded());
		HttpPost httpPost = new HttpPost(addr);
		httpPost.setEntity(entity);
		httpPost.addHeader("Content-Type", PlhCMPSystem.PKIX_CMP_STRING);
		HttpResponse sendingRsponse = httpclient.execute(httpPost);
		
		Assert.assertTrue(sendingRsponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		InputStream inputStream = sendingRsponse.getEntity().getContent();
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(IOUtils.toByteArray(inputStream));
		PKIHeader pkiHeader = generalPKIMessage.getHeader();

		GeneralName responseSender = pkiHeader.getSender();
		if(responseSender==null)
			Assert.fail("Missing response sender");
		
		if(!PlhCMPSystem.getServerName().equals(responseSender.getName()))
			Assert.fail("Response not from sender");			

		if(!generalPKIMessage.hasProtection())
			Assert.fail("Receive request must be protected");
		
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(generalPKIMessage);

		if(protectedPKIMessage.hasPasswordBasedMacProtection())
			throw new UnsupportedOperationException("Mac based protection not supported by this version.");

		X509CertificateHolder senderCertificate = new X509CertificateHolderCollection(protectedPKIMessage.getCertificates())
			.findBySubjectName(responseSender.getName());

		if(senderCertificate==null) 
			Assert.fail("Missing sender certificate");
		
		HttpResponse res = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
		if(res.getStatusLine().getStatusCode()!=HttpStatus.SC_OK){
			Assert.fail("Response authenticity could not be verified");
		}
	}
}
