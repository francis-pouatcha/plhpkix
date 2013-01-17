package org.adorys.plh.pkix.server.cmp.utils;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.adorys.plh.pkix.server.cmp.messaging.CMPMessaging;

@ApplicationPath("/rest")
public class JaxRsActivator extends Application {

	@Override
	public Set<Class<?>> getClasses() {
		Set<Class<?>> classes = new HashSet<Class<?>>(super.getClasses());
		classes.add(CMPMessaging.class);
		return classes;
	}

}
