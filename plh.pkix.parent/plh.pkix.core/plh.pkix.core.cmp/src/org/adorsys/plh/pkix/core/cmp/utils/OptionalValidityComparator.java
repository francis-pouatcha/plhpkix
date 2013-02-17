package org.adorsys.plh.pkix.core.cmp.utils;

import java.util.Date;

public class OptionalValidityComparator {
	
	public static final boolean isNotBeforeCompatible(Date requested, Date provided){
		if(requested==null) return true;
		if(provided==null) return false;
		
		return requested.equals(provided) || requested.before(provided);
	}	
	public static final boolean isNotAfterCompatible(Date requested, Date provided){
		if(requested==null) return true;
		if(provided==null) return false;
		
		return requested.equals(provided) || requested.after(provided);
	}
}
