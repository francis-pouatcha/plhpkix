package org.adorys.plh.pkix.server.cmp.messaging;

import java.util.Date;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(AbstractCMPMessageData.class)
public abstract class AbstractCMPMessageData_ {

	public static volatile SingularAttribute<AbstractCMPMessageData, Date> messageTime;
	public static volatile SingularAttribute<AbstractCMPMessageData, Date> receptionTime;
	public static volatile SingularAttribute<AbstractCMPMessageData, byte[]> pkiMessage;
	public static volatile SingularAttribute<AbstractCMPMessageData, String> transactionID;
	public static volatile SingularAttribute<AbstractCMPMessageData, String> recipient;

}

