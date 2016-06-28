
package eu.organicity.accounts.permissions;

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

    // user id of organicity/fbuether
    // a.getUserRoles("0dfc01f7-a234-4cbc-8e70-7ae361127dd4");
  }
}
