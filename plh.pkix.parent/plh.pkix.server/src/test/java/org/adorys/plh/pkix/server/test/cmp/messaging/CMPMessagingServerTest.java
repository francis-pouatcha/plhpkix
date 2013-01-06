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
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.server.cmp.core.PlhCMPSystem;
import org.adorys.plh.pkix.server.cmp.core.utils.JaxRsActivator;
import org.adorys.plh.pkix.server.cmp.core.utils.KeyIdUtils;
import org.adorys.plh.pkix.server.cmp.core.utils.OptionalValidityHolder;
import org.adorys.plh.pkix.server.cmp.core.utils.RequestVerifier;
import org.adorys.plh.pkix.server.cmp.core.utils.UUIDUtils;
import org.adorys.plh.pkix.server.cmp.core.utils.V3CertificateUtils;
import org.adorys.plh.pkix.server.test.cmp.AbstractCMPMessagingServerTest;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.math.RandomUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ByteArrayEntity;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CertRepMessage;
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
import org.bouncycastle.util.Arrays;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
@RunAsClient
public class CMPMessagingServerTest {

    private static final String RESOURCE_PREFIX = JaxRsActivator.class.getAnnotation(ApplicationPath.class).value().substring(1);
	
    private static Provider provider = PlhCMPSystem.getProvider();
	private static final String SERVICE_NAME = "/sample";
	   
    @Deployment(testable=false)
    public static WebArchive createDeployment() {
    	return AbstractCMPMessagingServerTest.createDeployment();
    }

    @ArquillianResource
    URL deploymentUrl;

	@Test
	@Ignore
	public void testSendReceive() throws Exception {
		
		// Generate a key pair for the new EndEntity
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", provider);
        kGen.initialize(512);
        KeyPair senderKeyPair = kGen.generateKeyPair();
        // Self sign the certificate
        String endEntityName = "CN=Francis Pouatcha";
        X509CertificateHolder senderCert = V3CertificateUtils.makeSelfV3Certificate(senderKeyPair, endEntityName, senderKeyPair, endEntityName, provider);
        byte[] sendeKeyId = KeyIdUtils.getSubjectKeyIdentifierAsByteString(senderCert);

        GeneralName sender = new GeneralName(new X500Name(endEntityName));
        // first initialization request must be sent to the server
        X500Name recipientX500Name = new X500Name(PlhCMPSystem.getServerName());
        GeneralName recipient = new GeneralName(recipientX500Name);

        ContentSigner senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(senderKeyPair.getPrivate());
		
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
                                                  .setTransactionID(UUIDUtils.newUUIDAsBytes())
                                                  .build(senderSigner);
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		
		String addr = deploymentUrl.toString()+ RESOURCE_PREFIX + SERVICE_NAME +"/req";
		HttpResponse sendingRsponse = Request.Post(addr)
				.body(new ByteArrayEntity(pkiMessage.getEncoded(), PlhCMPSystem.PKIX_CMP_CONTENT_TYPE))
				.execute()
				.returnResponse();
		Assert.assertTrue(sendingRsponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		InputStream inputStream = sendingRsponse.getEntity().getContent();
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(IOUtils.toByteArray(inputStream));
		PKIHeader pkiHeader = generalPKIMessage.getHeader();
		// Check if the message is addressed to the server. 
		// If yes reply synchronously

		GeneralName responseSender = pkiHeader.getSender();
		if(responseSender==null)
			Assert.fail("Missing response sender");
		String senderName = responseSender.toString();

		if(!generalPKIMessage.hasProtection())
			Assert.fail("Receive request must be protected");
		
		ProtectedPKIMessage protectedPKIMessage = new ProtectedPKIMessage(generalPKIMessage);

		if(protectedPKIMessage.hasPasswordBasedMacProtection())
			throw new UnsupportedOperationException("Mac based protection not supported by this version.");

		X509CertificateHolder[] certificates = protectedPKIMessage.getCertificates();
		X509CertificateHolder senderCertificate = null;
		for (X509CertificateHolder x509CertificateHolder : certificates) {
			if(senderName.equals(x509CertificateHolder.getSubject().toString())){
				senderCertificate = x509CertificateHolder;
			}
		}
		
		if(senderCertificate==null) 
			Assert.fail("Response not from server");
		
		Response verifiedRequest = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
		if(verifiedRequest.getStatus()!=Status.OK.getStatusCode()){
			Assert.fail("Response not from server");
		}
	}

	@Ignore
	public void testMessageOrder() throws OperatorCreationException, GeneralSecurityException, IOException, CertException, CMPException {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", provider);

        kGen.initialize(512);

        KeyPair senderKeyPair = kGen.generateKeyPair();
        X509CertificateHolder senderCert = V3CertificateUtils.makeSelfV3Certificate(senderKeyPair, "CN=Test Sender", senderKeyPair, "CN=Test Sender", provider);
        byte[] senderCertKeyIdentifier = KeyIdUtils.getSubjectKeyIdentifierAsByteString(senderCert);

        GeneralName sender = new GeneralName(new X500Name("CN=Test Sender"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Test Recip"));

        KeyPair recipientKeyPair = kGen.generateKeyPair();
        X509CertificateHolder recipientCert = V3CertificateUtils.makeSelfV3Certificate(recipientKeyPair, "CN=Test Recipient", recipientKeyPair, "CN=Test Recipient", provider);
        byte[] recipientKeyIdentifier = KeyIdUtils.getSubjectKeyIdentifierAsByteString(recipientCert);
        
        ContentSigner senderSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(senderKeyPair.getPrivate());
		
        byte[] transactionId1 = UUIDUtils.newUUIDAsBytes();
        ProtectedPKIMessage mainMessage = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(senderCert)
                                                  .setMessageTime(new Date())
                                                  .setRecipKID(recipientKeyIdentifier)
                                                  .setSenderKID(senderCertKeyIdentifier)
                                                  .setSenderNonce(UUIDUtils.newUUIDAsBytes())
                                                  .setTransactionID(transactionId1)
                                                  .build(senderSigner);
		PKIMessage pkiMessage = mainMessage.toASN1Structure();
		HttpResponse sendingRsponse = Request.Post(deploymentUrl.toString()+ RESOURCE_PREFIX + "/messaging/send")
					.body(new ByteArrayEntity(pkiMessage.getEncoded(), PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute().returnResponse();
		Assert.assertTrue(sendingRsponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode());

        byte[] transactionId2 = UUIDUtils.newUUIDAsBytes();
        mainMessage = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(senderCert)
                                                  .setMessageTime(new Date())
                                                  .setRecipKID(recipientKeyIdentifier)
                                                  .setSenderKID(senderCertKeyIdentifier)
                                                  .setSenderNonce(UUIDUtils.newUUIDAsBytes())
                                                  .setTransactionID(transactionId2)
                                                  .build(senderSigner);
		pkiMessage = mainMessage.toASN1Structure();
		sendingRsponse = Request.Post(deploymentUrl.toString()+ RESOURCE_PREFIX + "/messaging/send")
					.body(new ByteArrayEntity(pkiMessage.getEncoded(), PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute().returnResponse();
		Assert.assertTrue(sendingRsponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
        ContentSigner recipientSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(recipientKeyPair.getPrivate());
		ProtectedPKIMessage receiveMessage = new ProtectedPKIMessageBuilder(recipient, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(recipientCert)
                                                  .setMessageTime(new Date())
                                                  .setRecipKID(recipientKeyIdentifier)
                                                  .setSenderKID(recipientKeyIdentifier)
                                                  .setSenderNonce(UUIDUtils.newUUIDAsBytes())
                                                  .setTransactionID(UUIDUtils.newUUIDAsBytes())
                                                  .build(recipientSigner);
		PKIMessage recipPkiMessage = receiveMessage.toASN1Structure();
		HttpResponse receivingResponse = Request.Post(deploymentUrl.toString()+ RESOURCE_PREFIX + "/messaging/receive")
					.body(new ByteArrayEntity(recipPkiMessage.getEncoded(), PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute().returnResponse();
		Assert.assertTrue(receivingResponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		InputStream inputStream = receivingResponse.getEntity().getContent();

		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(IOUtils.toByteArray(inputStream));
		
		PKIHeader pkiHeader = generalPKIMessage.getHeader();
		Assert.assertTrue("Receive request must be a signed message", generalPKIMessage.hasProtection());
		Assert.assertTrue("Transaction id not identical",Arrays.areEqual(transactionId1, pkiHeader.getTransactionID().getOctets()));

        recipientSigner = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(provider).build(recipientKeyPair.getPrivate());
		receiveMessage = new ProtectedPKIMessageBuilder(recipient, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(recipientCert)
                                                  .setMessageTime(new Date())
                                                  .setRecipKID(recipientKeyIdentifier)
                                                  .setSenderKID(recipientKeyIdentifier)
                                                  .setSenderNonce(UUIDUtils.newUUIDAsBytes())
                                                  .setTransactionID(UUIDUtils.newUUIDAsBytes())
                                                  .build(recipientSigner);
		recipPkiMessage = receiveMessage.toASN1Structure();
		receivingResponse = Request.Post(deploymentUrl.toString()+ RESOURCE_PREFIX + "/messaging/receive")
					.body(new ByteArrayEntity(recipPkiMessage.getEncoded(), PlhCMPSystem.PKIX_CMP_CONTENT_TYPE)).execute().returnResponse();
		Assert.assertTrue(receivingResponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		inputStream = receivingResponse.getEntity().getContent();

		generalPKIMessage = new GeneralPKIMessage(IOUtils.toByteArray(inputStream));
		
		pkiHeader = generalPKIMessage.getHeader();
		Assert.assertTrue("Receive request must be a signed message", generalPKIMessage.hasProtection());
		Assert.assertTrue("Transaction id not identical",Arrays.areEqual(transactionId2, pkiHeader.getTransactionID().getOctets()));
	}
}
