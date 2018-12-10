package org.sdrc.usermgmt.core.web;

import java.security.Principal;
import java.util.Map;

import org.sdrc.usermgmt.model.UserModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

	@Autowired(required=false)
	private TokenStore tokenStore;
	
	/**
	 * It extracts the user details from jwt access-token.
	 * 
	 * @param auth
	 * @return
	 */
	@ConditionalOnExpression("'${application.security.type}'=='jwt-both' OR "
			+ "'${application.security.type}'=='jwt-resserver' "
			+ "OR '${application.security.type}'=='jwt-oauthserver'")
	@RequestMapping(value = "/oauth/user", method = RequestMethod.GET)
	public Map<String, Object> getExtraInfo(OAuth2Authentication auth) {
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
		OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());
		return accessToken.getAdditionalInformation();
	}

	/**
	 * It retrieves the user deatils.
	 * @param principal
	 * @return
	 */
	@ConditionalOnExpression("'${application.security.type}'=='oauth2-both' OR "
			+ "'${application.security.type}'=='basic' "
			+ "OR '${application.security.type}'=='oauth2-oauthserver'")
	@RequestMapping(value = "/user", method = RequestMethod.GET)
	public UserModel principal(Principal principal) {

		return (UserModel) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	}
	
}
