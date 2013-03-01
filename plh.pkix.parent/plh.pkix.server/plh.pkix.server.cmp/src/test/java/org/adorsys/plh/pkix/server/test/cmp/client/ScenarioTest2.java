package org.adorsys.plh.pkix.server.test.cmp.client;

import java.net.URL;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Response.Status;

import org.adorsys.plh.pkix.client.cmp.CMPMessagingClient;
import org.adorsys.plh.pkix.core.cmp.stores.PendingCertAnnouncements2;
import org.adorsys.plh.pkix.core.cmp.stores.PendingRequests;
import org.adorsys.plh.pkix.core.cmp.stores.PendingResponses2;
import org.adorsys.plh.pkix.core.utils.store.CertificateStore;
import org.adorsys.plh.pkix.core.utils.store.InMemoryCertificateStore;
import org.adorsys.plh.pkix.core.utils.store.InMemoryPrivateKeyHolder;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.adorsys.plh.pkix.server.cmp.utils.JaxRsActivator;
import org.adorsys.plh.pkix.server.test.cmp.AbstractCMPMessagingServerTest;
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

		// Tha admin client
		X500Name adminX500Name = X500NameHelper.makeX500Name("admin", "admin@plhpkixtest.biz");
		CertificateStore adminCertificateStore = new InMemoryCertificateStore();
		CMPMessagingClient adminClient = new CMPMessagingClient(adminX500Name, addressPrefix, 
				new InMemoryPrivateKeyHolder(), adminCertificateStore, 
				new PendingRequests(), new PendingCertAnnouncements2(), new PendingResponses2());

		// Francis
		X500Name francisX500Name = X500NameHelper.makeX500Name("francis", "francis@plhpkixtest.biz");
		CertificateStore francisCertificateStore = new InMemoryCertificateStore();
		CMPMessagingClient francisClient = new CMPMessagingClient(francisX500Name, addressPrefix, 
				new InMemoryPrivateKeyHolder(), francisCertificateStore, 
				new PendingRequests(), new PendingCertAnnouncements2(), new PendingResponses2());
		
		adminClient.initKeyPair();
		
		// 1
		HttpResponse initialize = adminClient.initialize(adminX500Name);
		Assert.assertTrue(initialize.getStatusLine().getStatusCode()==HttpStatus.SC_OK);

		francisClient.initKeyPair();
		
		// 2
		HttpResponse initialize1 = francisClient.initialize(francisX500Name);
		Assert.assertTrue(initialize1.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		// 3
		HttpResponse requestCertificateResp = francisClient.requestCertificate(adminX500Name);
		Assert.assertTrue(requestCertificateResp.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		
		HttpResponse fetchRequestResponse = adminClient.fetch(adminX500Name);
		Assert.assertTrue(fetchRequestResponse.getStatusLine().getStatusCode()+"", 
				(fetchRequestResponse.getStatusLine().getStatusCode()==Status.OK.getStatusCode()||
						(fetchRequestResponse.getStatusLine().getStatusCode()==Status.NO_CONTENT.getStatusCode())));
		
		HttpResponse sendResponsesResp = adminClient.sendResponses(adminX500Name);
		Assert.assertTrue(sendResponsesResp.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		HttpResponse pollRequestsResp = francisClient.pollRequests(francisX500Name);
		Assert.assertTrue(pollRequestsResp.getStatusLine().getStatusCode()+"",pollRequestsResp.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
		
		Assert.assertNotNull(francisCertificateStore.getCertificate(francisX500Name, francisX500Name));

		HttpResponse announceCertificates = francisClient.announceCertificates();
		Assert.assertTrue(announceCertificates.getStatusLine().getStatusCode()==Status.OK.getStatusCode());
//		Assert.assertNotNull(adminCertificateStore.getCertificate(francisX500Name, adminX500Name));
	}
}
