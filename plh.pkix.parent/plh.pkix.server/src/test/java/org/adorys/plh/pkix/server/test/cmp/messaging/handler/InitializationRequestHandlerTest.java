package org.adorys.plh.pkix.server.test.cmp.messaging.handler;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Provider;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.server.cmp.core.PlhCMPSystem;
import org.adorys.plh.pkix.server.cmp.core.initrequest.InitializationRequestBuilder;
import org.adorys.plh.pkix.server.cmp.core.initrequest.InitializationRequestHolder;
import org.adorys.plh.pkix.server.cmp.core.initrequest.InitializationResponseProcessor;
import org.adorys.plh.pkix.server.cmp.core.message.PkiMessageConformity;
import org.adorys.plh.pkix.server.cmp.core.stores.CertificateStore;
import org.adorys.plh.pkix.server.cmp.core.utils.GeneralNameHolder;
import org.adorys.plh.pkix.server.cmp.core.utils.JaxRsActivator;
import org.adorys.plh.pkix.server.cmp.core.utils.RequestVerifier;
import org.adorys.plh.pkix.server.cmp.core.utils.X509CertificateHolderCollection;
import org.adorys.plh.pkix.server.test.cmp.AbstractCMPMessagingServerTest;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ByteArrayEntity;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.operator.OperatorCreationException;
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
public class InitializationRequestHandlerTest {

    public static final String RESOURCE_PREFIX = JaxRsActivator.class.getAnnotation(ApplicationPath.class).value().substring(1);
	public static Provider provider = PlhCMPSystem.getProvider();
	public static final String SERVICE_NAME = "/messaging";

    @Deployment(testable=false)
    public static WebArchive createDeployment() {
    	return AbstractCMPMessagingServerTest.createDeployment();
    }

    @ArquillianResource
    URL deploymentUrl;
	
	@Test
	@Ignore
	public void test() throws OperatorCreationException, GeneralSecurityException, IOException, CertException, CMPException {
//		
//		InitializationRequestHolder initializationRequestHolder = new InitializationRequestBuilder()
//			.withEndEntityName(new X500Name("CN=Francis Pouatcha"))
//			.withRecipientX500Name(new X500Name(PlhCMPSystem.getServerName()))
//			.build();
//
//		PKIMessage pkiMessage = initializationRequestHolder.getPkiMessage();
//		String addr = deploymentUrl.toString()+ RESOURCE_PREFIX + SERVICE_NAME + "/req";
//		HttpResponse sendingRsponse = Request
//				.Post(addr)
//				.body(new ByteArrayEntity(pkiMessage.getEncoded(), PlhCMPSystem.PKIX_CMP_CONTENT_TYPE))
//				.execute()
//				.returnResponse();
//		Assert.assertTrue(sendingRsponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
//		
//		InputStream inputStream = sendingRsponse.getEntity().getContent();
//		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(IOUtils.toByteArray(inputStream));
//
//		// Check message conformity
//		ProtectedPKIMessage protectedPKIMessage = PkiMessageConformity.check(generalPKIMessage);
//		
//		// The client's certificate store
//		CertificateStore certificateStore = CertificateStore.getInstance(new X500Name("CN="+getClass().getSimpleName()));		
//
//		// Verify the response. In the very first case, the certificate used to sign the response will not
//		// be in the store.
//		X509CertificateHolder senderCertificate;
//		X500Name responseSenderX500Name = initializationRequestHolder.getRecipientX500Name();
//		if(certificateStore.isEmpty() && responseSenderX500Name.toString().equals(PlhCMPSystem.getServerName())){
//			GeneralNameHolder senderHolder = new GeneralNameHolder(protectedPKIMessage.getHeader().getSender());
//			Assert.assertEquals(initializationRequestHolder.getRecipientX500Name(), senderHolder.getX500Name());		
//			senderCertificate = new X509CertificateHolderCollection(protectedPKIMessage.getCertificates())
//				.findBySubjectName(initializationRequestHolder.getRecipientX500Name());
//		} else {
//			senderCertificate = certificateStore.getCertificate(responseSenderX500Name);
//		}
//		
//		if(senderCertificate==null) 
//			Assert.fail("Missing sender certificate");
//		Response verifiedRequest = RequestVerifier.verifyRequest(protectedPKIMessage, senderCertificate);
//		if(verifiedRequest.getStatus()!=Status.OK.getStatusCode()){
//			Assert.fail("Response authenticity could not be verified");
//		}		
//		
//		CertTemplate certTemplate = initializationRequestHolder.getCertTemplate();
//		new InitializationResponseProcessor().setCertificateStore(certificateStore).process(certTemplate, protectedPKIMessage);
//		
//		X509CertificateHolder certificate = certificateStore.getCertificate(certTemplate.getSubject(), certTemplate.getIssuer());
//		Assert.assertNotNull(certificate);
	}

}
