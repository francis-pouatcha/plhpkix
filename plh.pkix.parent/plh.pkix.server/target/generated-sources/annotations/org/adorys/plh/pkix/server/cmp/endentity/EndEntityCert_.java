package org.adorys.plh.pkix.server.cmp.endentity;

import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(EndEntityCert.class)
public abstract class EndEntityCert_ {

	public static volatile SingularAttribute<EndEntityCert, String> id;
	public static volatile SingularAttribute<EndEntityCert, byte[]> certificate;
	public static volatile SingularAttribute<EndEntityCert, String> subjectName;
	public static volatile SingularAttribute<EndEntityCert, String> issuerName;
	public static volatile SingularAttribute<EndEntityCert, Integer> version;

}

