package org.adorsys.plh.pkix.core.utils;

import java.util.Collection;


public class BuilderChecker {
	
	private Class<?> builderClass;
	private boolean dirty;
	
	public BuilderChecker(Class<?> builderClass) {
		if(builderClass==null) throw new IllegalArgumentException("builderClass is null");
		this.builderClass = builderClass;
	}

	public BuilderChecker checkDirty(){
		if(dirty) throw new IllegalStateException(builderClass.getName() + "is dirty. Create a new instance."); 
		this.dirty=true;
		return this;
	}
	
	public BuilderChecker checkNull(Object... notNullParams){
		if(notNullParams!=null)
			for (Object o : notNullParams) {
				if(o==null)throw new IllegalArgumentException(builderClass.getName() + " Check builder documentation. None of the params passed to this builder checker might be null");
			}
		return this;
	}

	public BuilderChecker checkEmpty(Collection<?>... nonEmptyParams){
		if(nonEmptyParams!=null)
			for (Collection<?> collection : nonEmptyParams) {
				if(collection.isEmpty())throw new IllegalArgumentException(builderClass.getName() + " Check builder documentation. None of the params passed to this builder checker might be empty");
			}
		return this;
	}

	public void checkEmpty(Object[]... nonEmptyParams) {
		if(nonEmptyParams!=null)
			for (Object[] objects : nonEmptyParams) {
				if(objects.length==0)throw new IllegalArgumentException(builderClass.getName() + " Check builder documentation. None of the params passed to this builder checker might be empty");
			}
	}
}
