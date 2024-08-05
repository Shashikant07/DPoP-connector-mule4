package org.mule.extension.DPoP.internal;

import org.mule.runtime.api.meta.ExpressionSupport;
import org.mule.runtime.extension.api.annotation.Expression;
import org.mule.runtime.extension.api.annotation.param.Parameter;
import org.mule.runtime.extension.api.annotation.param.display.DisplayName;
import org.mule.runtime.extension.api.annotation.param.display.Summary;
import org.mule.runtime.extension.api.annotation.values.OfValues;

public class DPoPParameter {
	
	 @Parameter
	 @Expression(ExpressionSupport.SUPPORTED)
	 @DisplayName("DPoP Url")
	 @Summary("Enter your url")
	 String url;
	
	 @Parameter
	 @OfValues(DPoPPriority.class)
	 @Expression(ExpressionSupport.SUPPORTED)
	 @DisplayName("Method")
	 @Summary("Select the priority from drop-down")
	 String priority;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getPriority() {
		return priority;
	}

	public void setPriority(String priority) {
		this.priority = priority;
	}
	 
	 
}
