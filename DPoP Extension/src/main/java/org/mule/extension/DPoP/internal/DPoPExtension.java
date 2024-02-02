package org.mule.extension.DPoP.internal;

import org.mule.runtime.extension.api.annotation.Extension;
import org.mule.runtime.extension.api.annotation.Configurations;
import org.mule.runtime.extension.api.annotation.dsl.xml.Xml;

@Xml(prefix = "dpop")
@Extension(name = "DPoP")
@Configurations(DPoPConfiguration.class)
public class DPoPExtension {

}
