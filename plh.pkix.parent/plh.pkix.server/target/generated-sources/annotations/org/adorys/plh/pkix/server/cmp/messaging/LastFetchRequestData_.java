package org.adorys.plh.pkix.server.cmp.messaging;

import java.util.Date;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(LastFetchRequestData.class)
public abstract class LastFetchRequestData_ {

	public static volatile SingularAttribute<LastFetchRequestData, byte[]> fetchMessage;
	public static volatile SingularAttribute<LastFetchRequestData, String> id;
	public static volatile SingularAttribute<LastFetchRequestData, Date> messageTime;
	public static volatile SingularAttribute<LastFetchRequestData, Date> receptionTime;
	public static volatile SingularAttribute<LastFetchRequestData, String> name;
	public static volatile SingularAttribute<LastFetchRequestData, String> keyId;

}

