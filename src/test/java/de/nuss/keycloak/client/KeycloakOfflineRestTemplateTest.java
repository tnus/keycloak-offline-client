package de.nuss.keycloak.client;

import static org.junit.Assert.assertEquals;

import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Ignore
public class KeycloakOfflineRestTemplateTest {

	@Test
	public void usernameAndPassword() throws InterruptedException {
		KeycloakOfflineClientRequestFactory factory = new KeycloakOfflineClientRequestFactory(
				"http://keycloak-authserver/auth", "TestRealm", "myClient", "user1", "pwd");
		KeycloakOfflineRestTemplate restTemplate = new KeycloakOfflineRestTemplate(factory);

		ResponseEntity<String> result = restTemplate.getForEntity("http://localhost/sampleService", String.class);
		assertEquals(200, result.getStatusCodeValue());
		log.info(result.getBody());
	}
}
