
package eu.organicity.accounts.permissions;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// import ch.qos.logback.classic.Logger;
// import ch.qos.logback.classic.Level;


public class App
{
  public static void main( String[] args )
  {
    // up the logging level.
    ((ch.qos.logback.classic.Logger)LoggerFactory.
     getLogger(Logger.ROOT_LOGGER_NAME)).
      setLevel(ch.qos.logback.classic.Level.TRACE);


    Accounts a = new Accounts();

    String token = a.login();

    Logger log = LoggerFactory.getLogger(App.class);

    log.info("Got token: " + token);

    // user id of organicity/fbuether
    String userId = "0dfc01f7-a234-4cbc-8e70-7ae361127dd4";

    List<String> roles = a.getUserRoles(userId);
    if (roles != null) {
      log.info("got roles:");
      for(String role : roles) {
        log.info("Role " + role);
      }
    }

    a.setUserRole(userId, "scenarios:admin");
  }
}
