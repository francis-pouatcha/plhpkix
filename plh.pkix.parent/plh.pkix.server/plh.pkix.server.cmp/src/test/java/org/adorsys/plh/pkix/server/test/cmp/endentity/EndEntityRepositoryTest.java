package org.adorsys.plh.pkix.server.test.cmp.endentity;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;

import javax.ejb.EJB;

import org.adorsys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorsys.plh.pkix.core.utils.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.store.CertificateStore;
import org.adorsys.plh.pkix.core.utils.store.InMemoryCertificateStore;
import org.adorsys.plh.pkix.core.utils.store.InMemoryPrivateKeyHolder;
import org.adorsys.plh.pkix.core.utils.store.PrivateKeyHolder;
import org.adorsys.plh.pkix.core.utils.x500.X500NameHelper;
import org.adorsys.plh.pkix.server.cmp.endentity.EndEntityCert;
import org.adorsys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.adorsys.plh.pkix.server.cmp.endentity.EndEntityInitializer;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.ArchivePaths;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class EndEntityRepositoryTest {

    @Deployment
    public static WebArchive createDeployment() {
		WebArchive webArchive = ShrinkWrap.create(WebArchive.class, "serverInitializerTest.war")
        		.addPackage(EndEntityInitializer.class.getPackage())
        		.addPackage(EndEntityCertRepository.class.getPackage())
        		.addPackages(true, PlhCMPSystem.class.getPackage())
        		.addPackages(true, ProviderUtils.class.getPackage())
        		.addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
        		.addAsWebInfResource(new File("src/main/webapp/WEB-INF/jboss-deployment-structure.xml"), ArchivePaths.create("jboss-deployment-structure.xml"))
                .addAsResource("test-persistence.xml", "META-INF/persistence.xml");
    	File[] files = Maven.resolver().loadPomFromFile("pom.xml").importRuntimeDependencies().as(File.class);		
		webArchive = webArchive.addAsLibraries(files);
		return webArchive;
    }
    
    @EJB
    EndEntityInitializer serverInitializer;

    @EJB
    EndEntityCertRepository endEntityCertRepository;
    
	@Test
	public void test() throws NoSuchAlgorithmException {

		X500Name fpEndEntityX500Name = X500NameHelper.makeX500Name("Francis Pouatcha", "fpo@plhpkix.biz");
		PrivateKeyHolder fpPrivateKeyHolder = new InMemoryPrivateKeyHolder();
		CertificateStore fpCertificateStore = new InMemoryCertificateStore();
		new KeyPairBuilder()
			.withEndEntityName(fpEndEntityX500Name)
			.withPrivateKeyHolder(fpPrivateKeyHolder)
			.withCertificateStore(fpCertificateStore)
			.build0();
		X509CertificateHolder fpSubjectCertificate = fpCertificateStore.getCertificate(fpEndEntityX500Name);
		endEntityCertRepository.storeEndEntityCert(fpSubjectCertificate);
		PrivateKey fpPrivateKey = fpPrivateKeyHolder.getPrivateKey(fpSubjectCertificate);
		List<EndEntityCert> fps = endEntityCertRepository.findEndEntityCertBySubjectName(fpEndEntityX500Name);
		Assert.assertTrue(fps.size()==1);
		
		X500Name ssEndEntityX500Name = X500NameHelper.makeX500Name("Sandro Sonntag", "sso@plhpkix.biz");
		PrivateKeyHolder ssPrivateKeyHolder = new InMemoryPrivateKeyHolder();
		CertificateStore ssCertificateStore = new InMemoryCertificateStore();
		new KeyPairBuilder()
			.withEndEntityName(ssEndEntityX500Name)
			.withPrivateKeyHolder(ssPrivateKeyHolder)
			.withCertificateStore(ssCertificateStore )
			.build0();
		X509CertificateHolder ssSubjectCertificate = ssCertificateStore.getCertificate(ssEndEntityX500Name);
		endEntityCertRepository.storeEndEntityCert(ssSubjectCertificate);
		List<EndEntityCert> sss = endEntityCertRepository.findEndEntityCertBySubjectName(ssEndEntityX500Name);
		Assert.assertTrue(sss.size()==1);
		
		X509CertificateHolder ssFpCertificate = V3CertificateUtils.makeV3Certificate(ssSubjectCertificate, 
				fpPrivateKey, fpSubjectCertificate, new Date(), DateUtils.addYears(new Date(), 1), ProviderUtils.bcProvider);
		endEntityCertRepository.storeEndEntityCert(ssFpCertificate);
		
		fps = endEntityCertRepository.findEndEntityCertBySubjectName(fpEndEntityX500Name);
		Assert.assertTrue(fps.size()==1);

		sss = endEntityCertRepository.findEndEntityCertBySubjectName(ssEndEntityX500Name);
		Assert.assertTrue(sss.size()==2);
		
		List<EndEntityCert> ssfps = endEntityCertRepository.findEndEntityCertBySubjectAndIssuerName(
				ssEndEntityX500Name, fpEndEntityX500Name);
		Assert.assertTrue(ssfps.size()==1);
	}
}
