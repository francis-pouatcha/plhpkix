package org.adorys.plh.pkix.server.test.cmp.client;

import java.net.URL;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Response.Status;

import org.adorsys.plh.pkix.client.cmp.CMPMessagingClient;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PendingCertAnn;
import org.adorys.plh.pkix.server.cmp.utils.JaxRsActivator;
import org.adorys.plh.pkix.server.test.cmp.AbstractCMPMessagingServerTest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.x500.X500Name;
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
public class ScenarioTest2 {

    private static final String RESOURCE_PREFIX = JaxRsActivator.class.getAnnotation(ApplicationPath.class).value().substring(1);
	
    private static final String SERVICE_NAME = "/messaging";

    @Deployment(testable=false)
    public static WebArchive createDeployment() {
    	return AbstractCMPMessagingServerTest.createDeployment();
    }

    @ArquillianResource
    URL deploymentUrl;
    
	@Test
	public void test() throws Exception{
		String addressPrefix = deploymentUrl.toString()+ RESOURCE_PREFIX + SERVICE_NAME;

		String adminX500NameString = "CN=Admin";
		CMPMessagingClient adminClient = new CMPMessagingClient()
			.withClientName(adminX500NameString)
			.withAddressPrefix(addressPrefix);
		
		String francisX500NameString = "CN=Francis Pouatcha";
		CMPMessagingClient francisClient = new CMPMessagingClient()
		.withClientName(francisX500NameString)
		.withAddressPrefix(addressPrefix);
		
		adminClient.initKeyPair();
		
		// 1
		HttpResponse initialize = adminClient.initialize(adminX500NameString);
		Assert.assertTrue(initialize.getStatusLine().getStatusCode()==HttpStatus.SC_OK);

		francisClient.initKeyPair();
		
		// 2
		HttpResponse initialize1 = francisClient.initialize(francisX500NameString);
		Assert.assertTrue(initialize1.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		// 3
		HttpResponse requestCertificateResp = francisClient.requestCertificate(adminX500NameString);
		Assert.assertTrue(requestCertificateResp.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		
		HttpResponse fetchRequestResponse = adminClient.fetchRequests(10, adminX500NameString);
		Assert.assertTrue(fetchRequestResponse.getStatusLine().getStatusCode()+"", fetchRequestResponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		HttpResponse sendResponsesResp = adminClient.sendResponses(adminX500NameString);
		Assert.assertTrue(sendResponsesResp.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		HttpResponse pollRequestsResp = francisClient.pollRequests(francisX500NameString);
		Assert.assertTrue(pollRequestsResp.getStatusLine().getStatusCode()+"",pollRequestsResp.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		X500Name francisX500Names = new X500Name(francisX500NameString);
		CertificateStore certificateStore = CertificateStore.getInstance(francisX500Names );
		Assert.assertNotNull(certificateStore);
		
		Assert.assertNotNull(certificateStore.getCertificate(francisX500Names, francisX500Names));
		X500Name adminX500Names = new X500Name(adminX500NameString);
		Assert.assertNotNull(certificateStore.getCertificate(francisX500Names, adminX500Names ));

		PendingCertAnn pendingCertAnn = PendingCertAnn.getInstance(francisX500Names);
		Assert.assertNotNull(pendingCertAnn);

		HttpResponse announceCertificates = francisClient.announceCertificates();
		Assert.assertTrue(announceCertificates.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
	}
}
