
package eu.organicity.accounts.permissions;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App
{
	public static void main( String[] args )
  {
    // up the logging level.
    ((ch.qos.logback.classic.Logger)LoggerFactory.
     getLogger(Logger.ROOT_LOGGER_NAME)).
      setLevel(ch.qos.logback.classic.Level.TRACE);

    String auth = args.length > 0
			? args[0]
			: "<INSERT TOKEN HERE>";

		Accounts a = new Accounts();
		String token = a.login(auth);

		if (token == null) {
      LoggerFactory.getLogger(App.class).
        warn("could not aquire auth token, exiting.");
      return;
    }

		Logger log = LoggerFactory.getLogger(App.class);

		String userId = "0dfc01f7-a234-4cbc-8e70-7ae361127dd4";

    a.setUserRole(userId, "demo:");

		// user id of organicity/fbuether
		List<String> roles = a.getUserRoles(userId, "account");
		if (roles != null) {
      log.info("got roles:");
      for(String role : roles) {
        log.info("Role " + role);
      }
    }


	}
}
