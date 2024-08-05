package org.mule.extension.DPoP.internal;

import java.util.Set;

import org.mule.runtime.api.value.Value;
import org.mule.runtime.extension.api.values.ValueBuilder;
import org.mule.runtime.extension.api.values.ValueProvider;
import org.mule.runtime.extension.api.values.ValueResolvingException;

public class DPoPPriority implements ValueProvider{
	 @Override
	    public Set<Value> resolve() throws ValueResolvingException {
	    	// TODO Auto-generated method stub
	    	return ValueBuilder.getValuesFor("GET","POST","PATCH","PUT","DELETE");
	    }
}
