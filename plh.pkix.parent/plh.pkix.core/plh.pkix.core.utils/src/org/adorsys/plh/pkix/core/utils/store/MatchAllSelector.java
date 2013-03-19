package org.adorsys.plh.pkix.core.utils.store;

import org.bouncycastle.util.Selector;

public class MatchAllSelector implements Selector {

    public boolean match(Object obj){return true;}

    public Object clone(){return this;}
	
}
