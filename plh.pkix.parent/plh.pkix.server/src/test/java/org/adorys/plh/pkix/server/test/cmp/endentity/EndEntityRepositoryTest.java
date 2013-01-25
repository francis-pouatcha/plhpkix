package org.adorys.plh.pkix.server.test.cmp.endentity;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.List;

import javax.ejb.EJB;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.core.cmp.keypair.KeyPairBuilder;
import org.adorys.plh.pkix.core.cmp.stores.CertificateStore;
import org.adorys.plh.pkix.core.cmp.stores.PrivateKeyHolder;
import org.adorys.plh.pkix.core.cmp.utils.KeyIdUtils;
import org.adorys.plh.pkix.core.cmp.utils.V3CertificateUtils;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCert;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityInitializer;
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
        		.addPackage(PlhCMPSystem.class.getPackage())
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

		String endEntityName = "CN=Francis Pouatcha";
		X500Name fpEndEntityX500Name = new X500Name(endEntityName);
		PrivateKeyHolder privateKeyHolder = PrivateKeyHolder.getInstance(fpEndEntityX500Name);
		new KeyPairBuilder()
			.withEndEntityName(fpEndEntityX500Name)
			.withPrivateKeyHolder(privateKeyHolder)
			.build();
		CertificateStore fpCertificateStore = CertificateStore.getInstance(fpEndEntityX500Name);
		X509CertificateHolder fpSubjectCertificate = fpCertificateStore.getCertificate(fpEndEntityX500Name);
		endEntityCertRepository.storeEndEntityCert(fpSubjectCertificate);
		PrivateKey fpPrivateKey = PrivateKeyHolder.getInstance(fpEndEntityX500Name).getPrivateKey(KeyIdUtils.getSubjectKeyIdentifierAsOctetString(fpSubjectCertificate));
		List<EndEntityCert> fps = endEntityCertRepository.findEndEntityCertBySubjectName(fpEndEntityX500Name);
		Assert.assertTrue(fps.size()==1);
		
		X500Name ssEndEntityX500Name = new X500Name("CN=Sandro Sonntag");
		PrivateKeyHolder ssPrivateKeyHolder = PrivateKeyHolder.getInstance(ssEndEntityX500Name);
		new KeyPairBuilder()
			.withEndEntityName(ssEndEntityX500Name)
			.withPrivateKeyHolder(ssPrivateKeyHolder)
			.build();
		CertificateStore ssCertificateStore = CertificateStore.getInstance(ssEndEntityX500Name);
		X509CertificateHolder ssSubjectCertificate = ssCertificateStore.getCertificate(ssEndEntityX500Name);
		endEntityCertRepository.storeEndEntityCert(ssSubjectCertificate);
		List<EndEntityCert> sss = endEntityCertRepository.findEndEntityCertBySubjectName(ssEndEntityX500Name);
		Assert.assertTrue(sss.size()==1);
		
		
		X509CertificateHolder ssFpCertificate = V3CertificateUtils.makeV3Certificate(ssSubjectCertificate, fpPrivateKey,
				fpEndEntityX500Name.toString(), PlhCMPSystem.getProvider());
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
