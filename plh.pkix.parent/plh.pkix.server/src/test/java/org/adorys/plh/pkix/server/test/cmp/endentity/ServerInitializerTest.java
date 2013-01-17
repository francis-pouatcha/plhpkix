package org.adorys.plh.pkix.server.test.cmp.endentity;

import java.io.File;

import javax.ejb.EJB;

import org.adorys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityInitializer;
import org.adorys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
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
public class ServerInitializerTest {

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
    
	@Test
	public void test() {
		X509CertificateHolder serverCertificateHolder = serverInitializer.getServerCertificate();
		X500Name subject = serverCertificateHolder.getSubject();
		Assert.assertEquals(PlhCMPSystem.getServerName(), subject.toString());
	}

}
