package org.adorsys.plh.pkix.server.test.cmp;

import java.io.File;
import java.security.Provider;

import javax.ws.rs.ApplicationPath;

import org.adorsys.plh.pkix.core.cmp.PlhCMPSystem;
import org.adorsys.plh.pkix.core.utils.ProviderUtils;
import org.adorsys.plh.pkix.server.cmp.endentity.EndEntityCertRepository;
import org.adorsys.plh.pkix.server.cmp.messaging.CMPMessaging;
import org.adorsys.plh.pkix.server.cmp.utils.JaxRsActivator;
import org.jboss.shrinkwrap.api.ArchivePaths;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;

public abstract class AbstractCMPMessagingServerTest {

    public static final String RESOURCE_PREFIX = JaxRsActivator.class.getAnnotation(ApplicationPath.class).value().substring(1);
	public static final Provider provider = ProviderUtils.bcProvider;
	public static final String SERVICE_NAME = "/messaging";
	
    public static WebArchive createDeployment() {
    	WebArchive webArchive = ShrinkWrap.create(WebArchive.class, "test.war")
        		.addPackages(true, CMPMessaging.class.getPackage())
        		.addPackages(true, EndEntityCertRepository.class.getPackage())
        		.addPackages(true, JaxRsActivator.class.getPackage())
        		.addPackages(true, ProviderUtils.class.getPackage())
        		.addPackages(true, PlhCMPSystem.class.getPackage())
        		.addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
        		.addAsWebInfResource(new File("src/main/webapp/WEB-INF/web.xml"), ArchivePaths.create("web.xml"))
        		.addAsWebInfResource(new File("src/main/webapp/WEB-INF/jboss-deployment-structure.xml"), ArchivePaths.create("jboss-deployment-structure.xml"))
                .addAsResource("test-persistence.xml", "META-INF/persistence.xml");
		
    	File[] files = Maven.resolver().loadPomFromFile("pom.xml").importRuntimeDependencies().as(File.class);
		webArchive = webArchive.addAsLibraries(files);
		return webArchive;
    }
}
