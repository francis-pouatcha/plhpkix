package org.adorys.plh.pkix.server.test.cmp.messaging;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.adorys.plh.pkix.server.cmp.core.stores.CertificateStore;
import org.adorys.plh.pkix.server.cmp.core.stores.PendingCertAnn;
import org.adorys.plh.pkix.server.cmp.core.utils.JaxRsActivator;
import org.adorys.plh.pkix.server.test.cmp.AbstractCMPMessagingServerTest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.operator.OperatorCreationException;
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
public class ScenarioTest {

    private static final String RESOURCE_PREFIX = JaxRsActivator.class.getAnnotation(ApplicationPath.class).value().substring(1);
	
    private static final String SERVICE_NAME = "/messaging";

    @Deployment(testable=false)
    public static WebArchive createDeployment() {
    	return AbstractCMPMessagingServerTest.createDeployment();
    }

    @ArquillianResource
    URL deploymentUrl;
    
	@Test
	public void test() throws OperatorCreationException, GeneralSecurityException, IOException, CertException, CMPException{
		String addressPrefix = deploymentUrl.toString()+ RESOURCE_PREFIX + SERVICE_NAME;

		X500Name adminX500Name = new X500Name("CN=Admin");
		CMPMessagingClient adminClient = new CMPMessagingClient()
			.withClientName(adminX500Name)
			.withAddressPrefix(addressPrefix);
		
		X500Name francisX500Name = new X500Name("CN=Francis Pouatcha");
		CMPMessagingClient francisClient = new CMPMessagingClient()
		.withClientName(francisX500Name)
		.withAddressPrefix(addressPrefix);
		
		adminClient.initKeyPair();
		
		// 1
		Response initialize = adminClient.initialize(adminX500Name);
		Assert.assertTrue(initialize.getStatus()==Status.OK.getStatusCode());

		francisClient.initKeyPair();
		
		// 2
		Response initialize1 = francisClient.initialize(francisX500Name);
		Assert.assertTrue(initialize1.getStatus()==Status.OK.getStatusCode());
		
		// 3
		Response requestCertificateResp = francisClient.requestCertificate(adminX500Name);
		Assert.assertTrue(requestCertificateResp.getStatus()==Status.OK.getStatusCode());
		
		
		Response fetchRequestResponse = adminClient.fetchRequests(10, adminX500Name);
		Assert.assertTrue(fetchRequestResponse.getStatus()+"", fetchRequestResponse.getStatus()==Status.OK.getStatusCode());
		
		Response sendResponsesResp = adminClient.sendResponses(adminX500Name);
		Assert.assertTrue(sendResponsesResp.getStatus()==Status.OK.getStatusCode());
		
		Response pollRequestsResp = francisClient.pollRequests(francisX500Name);
		Assert.assertTrue(pollRequestsResp.getStatus()+"",pollRequestsResp.getStatus()==Status.OK.getStatusCode());
		CertificateStore certificateStore = CertificateStore.getInstance(francisX500Name);
		Assert.assertNotNull(certificateStore);
		
		Assert.assertNotNull(certificateStore.getCertificate(francisX500Name, francisX500Name));
		Assert.assertNotNull(certificateStore.getCertificate(francisX500Name, adminX500Name));

		PendingCertAnn pendingCertAnn = PendingCertAnn.getInstance(francisX500Name);
		Assert.assertNotNull(pendingCertAnn);

		Response announceCertificates = francisClient.announceCertificates();
		Assert.assertTrue(announceCertificates.getStatus()==Status.OK.getStatusCode());
	}
}
