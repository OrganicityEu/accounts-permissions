
package eu.organicity.accounts.permissions;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
	public static void main(String[] args) {
		// up the logging level.
		((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME))
				.setLevel(ch.qos.logback.classic.Level.TRACE);

		String auth = args.length > 0 ? args[0] : "<INSERT TOKEN HERE>";

		Accounts a = Accounts.withBasicAuth(auth);
		String token = a.getAuthToken();

		if (token == null) {
			LoggerFactory.getLogger(App.class).warn("could not aquire auth token, exiting.");
			return;
		}

		Logger log = LoggerFactory.getLogger(App.class);

		// User id of organicity/fbuether
		String userId = "0dfc01f7-a234-4cbc-8e70-7ae361127dd4";

		Boolean removeStatus = a.removeUserRole(userId, "demo:demo-role1");
		log.info("Remove role: " + removeStatus);

		Boolean setStatus = a.setUserRole(userId, "demo:demo-role1");
		log.info("Set role: " + setStatus);

		// Get all roles
		List<String> roles = a.getUserRoles(userId);
		if (roles != null) {
			log.info("got all roles (global)");
			for (String role : roles) {
				log.info("Role " + role);
			}
		}

		// Get all `demo roles`
		List<String> demoRoles = a.getUserRoles(userId, "demo");
		if (demoRoles != null) {
			log.info("got roles for client `demo`:");
			for (String role : demoRoles) {
				log.info("Role " + role);
			}
		}
		
		// Get all `demo roles`
		List<String> accountRoles = a.getUserRoles(userId, "account");
		if (accountRoles != null) {
			log.info("got roles for client `account`:");
			for (String role : accountRoles) {
				log.info("Role " + role);
			}
		}		
		
		
	}
}
