package org.mule.extension.DPoP.internal;

import java.util.HashSet;
import java.util.Set;

import org.mule.runtime.extension.api.annotation.error.ErrorTypeProvider;
import org.mule.runtime.extension.api.error.ErrorTypeDefinition;

public class DPoPErrorProvider implements ErrorTypeProvider{
	@Override
    public Set<ErrorTypeDefinition> getErrorTypes() {
        Set<ErrorTypeDefinition> errors = new HashSet<ErrorTypeDefinition>();
        errors.add(DPoPError.FILE_NOT_FOUND);
        errors.add(DPoPError.IO_ERROR);
        errors.add(DPoPError.INTERNAL_SERVER_ERROR);
        errors.add(DPoPError.NOT_FOUND);
        errors.add(DPoPError.FORBIDDEN);
        return errors;
    }
}
