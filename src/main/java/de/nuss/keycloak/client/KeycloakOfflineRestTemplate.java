package de.nuss.keycloak.client;

import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * This rest template uses an offline token for authentication. It uses an
 * access token. If this is not valid anymore a new one is retrieved.
 * 
 * @author Thorsten Nuss
 *
 */
public class KeycloakOfflineRestTemplate extends RestTemplate implements RestOperations {

	public KeycloakOfflineRestTemplate(KeycloakOfflineClientRequestFactory factory) {
		super(factory);
	}
}
