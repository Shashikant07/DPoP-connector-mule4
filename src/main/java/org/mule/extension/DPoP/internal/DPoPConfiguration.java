package org.mule.extension.DPoP.internal;

import org.mule.runtime.api.meta.ExpressionSupport;
import org.mule.runtime.api.meta.model.display.PathModel.Type;
import org.mule.runtime.extension.api.annotation.Expression;
import org.mule.runtime.extension.api.annotation.Operations;
import org.mule.runtime.extension.api.annotation.param.Parameter;
import org.mule.runtime.extension.api.annotation.param.display.DisplayName;
import org.mule.runtime.extension.api.annotation.param.display.Path;
import org.mule.runtime.extension.api.annotation.param.display.Summary;
import org.mule.runtime.extension.api.annotation.param.display.Text;

@Operations(DPoPOperations.class)
public class DPoPConfiguration {
 
  @Parameter
  @Summary("Enter access Token Url")
  @DisplayName("Token url")
  @Expression(ExpressionSupport.SUPPORTED)
  private String accessTokenUrl;
  
  @Parameter
  @Summary("Enter username")
  @DisplayName("Username")
  @Expression(ExpressionSupport.SUPPORTED)
  private String username;
  
  @Parameter
  @Summary("Enter Password")
  @DisplayName("Password")
  @Expression(ExpressionSupport.SUPPORTED)
  private String password;
  
  @Parameter
  @Summary("Enter private key path")
  @DisplayName("Private key")
  @Expression(ExpressionSupport.SUPPORTED)
  @Path(type = Type.FILE, acceptsUrls = true)
  private String privateKey;
  
  @Parameter
  @Summary("Enter public key path")
  @DisplayName("Public key")
  @Expression(ExpressionSupport.SUPPORTED)
  @Path(type = Type.FILE, acceptsUrls = true)
  private String publicKey;
  
  
  public String getUsername() {
	return username;
}

public void setUsername(String username) {
	this.username = username;
}

public String getPassword() {
	return password;
}

public void setPassword(String password) {
	this.password = password;
}

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

public String getAccessTokenUrl() {
	return accessTokenUrl;
}

public void setAccessTokenUrl(String accessTokenUrl) {
	this.accessTokenUrl = accessTokenUrl;
}
}
