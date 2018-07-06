package de.nuss.keycloak.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;

import org.keycloak.util.TokenUtil;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import lombok.extern.slf4j.Slf4j;

/**
 * This class can be used to resolve an open id token.
 * 
 * @author Thorsten Nuss
 *
 */
@Slf4j
public class JWTTokenResolver {

	public static final String AUTHORIZATION_HEADER = "Authorization";

	private String authServerUrl;

	private String clientId;

	private String realm;

	private String accessToken;

	private String refreshToken;

	private String username;

	private String password;

	private JWTTokenResolver(String authServerUrl, String realm, String clientId) {
		this.authServerUrl = authServerUrl;
		this.realm = realm;
		this.clientId = clientId;
	}

	public JWTTokenResolver(String authServerUrl, String realm, String clientId, String username, String password) {
		this(authServerUrl, realm, clientId);
		this.username = username;
		this.password = password;
	}

	public JWTTokenResolver(String authServerUrl, String realm, String clientId, String offlineToken) {
		this(authServerUrl, realm, clientId);
		this.refreshToken = offlineToken;
	}

	/**
	 * This method can be used to resolve the access token
	 * 
	 * @return
	 */
	public String getAccessToken() {
		try {

			// check if access token is present and not expired
			if (accessToken != null && !TokenUtil.getRefreshToken(accessToken).isExpired()) {
				return accessToken;
			}

			RestTemplate restTemplate = new RestTemplate();
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
			mapForm.add("client_id", clientId);

			// access token must be generated
			if (refreshToken != null && !TokenUtil.getRefreshToken(refreshToken).isExpired()) {
				log.debug("create new access token");
				mapForm.add("grant_type", "refresh_token");
				mapForm.add("refresh_token", refreshToken);
			} else {
				// use username and password
				mapForm.add("grant_type", "password");
				mapForm.add("username", username);
				mapForm.add("password", password);
			}

			HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);
			ResponseEntity<Object> response = restTemplate.exchange(getAuthServerURI(), HttpMethod.POST, request,
					Object.class);

			if (!HttpStatus.OK.equals(response.getStatusCode())) {
				throw new IllegalStateException(response.getStatusCodeValue() + ": " + response.getBody().toString());
			}

			LinkedHashMap<String, Object> map = (LinkedHashMap<String, Object>) response.getBody();
			this.accessToken = (String) map.get("access_token");
			String tokenType = (String) map.get("token_type");
			this.refreshToken = (String) map.get("refresh_token");
			int expires_in = (int) map.get("expires_in");
			String scope = (String) map.get("scope");

			log.trace("accesstoken: {}", accessToken);
			log.trace("tokenType: {}", tokenType);
			log.trace("refreshToken: {}", refreshToken);
			log.trace("expires_in: {}", expires_in);
			log.trace("scope: {}", scope);

			return accessToken;
		} catch (Exception e) {
			throw new IllegalStateException("access token cannot be retrieved!", e);
		}
	}

	private URI getAuthServerURI() throws URISyntaxException {
		return new URI(authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token");
	}
}
