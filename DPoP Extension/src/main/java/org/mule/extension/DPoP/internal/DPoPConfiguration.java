package org.mule.extension.DPoP.internal;

import org.mule.runtime.api.meta.ExpressionSupport;
import org.mule.runtime.extension.api.annotation.Expression;
import org.mule.runtime.extension.api.annotation.Operations;
import org.mule.runtime.extension.api.annotation.param.Parameter;
import org.mule.runtime.extension.api.annotation.param.display.DisplayName;
import org.mule.runtime.extension.api.annotation.param.display.Summary;

@Operations(DPoPOperations.class)
public class DPoPConfiguration {

  @Parameter
  @Summary("Enter your private key")
  @DisplayName("Private Key")
  @Expression(ExpressionSupport.SUPPORTED)
  private String privateKey;
  
  @Parameter
  @Summary("Enter your public key")
  @DisplayName("Public Key")
  @Expression(ExpressionSupport.SUPPORTED)
  private String publicKey;
  
  @Parameter
  @Summary("File Path")
  @DisplayName("File Path")
  @Expression(ExpressionSupport.SUPPORTED)
  private String filePath;
  
 
  public String getPrivateKey() {
	return privateKey;
}

public void setPrivateKey(String privateKey) {
	this.privateKey = privateKey;
}

public String getPublicKey() {
	return publicKey;
}

public void setPublicKey(String publicKey) {
	this.publicKey = publicKey;
}

public String getFilePath() {
	return filePath;
}

public void setFilePath(String filePath) {
	this.filePath = filePath;
}

}
