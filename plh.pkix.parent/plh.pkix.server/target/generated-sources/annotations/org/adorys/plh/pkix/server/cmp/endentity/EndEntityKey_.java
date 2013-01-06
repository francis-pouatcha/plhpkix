package org.adorys.plh.pkix.server.cmp.endentity;

import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(EndEntityKey.class)
public abstract class EndEntityKey_ {

	public static volatile SingularAttribute<EndEntityKey, String> id;
	public static volatile SingularAttribute<EndEntityKey, String> subjectName;
	public static volatile SingularAttribute<EndEntityKey, byte[]> encryptedKeyData;
	public static volatile SingularAttribute<EndEntityKey, Integer> version;

}

