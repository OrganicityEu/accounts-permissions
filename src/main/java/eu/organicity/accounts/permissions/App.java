
package eu.organicity.accounts.permissions;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.organicity.JwtParser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;

public class App
{
	public static void exampleGetRoles(String auth) {
	    Accounts a = new Accounts(auth);

	    System.out.println(auth);

	    String token = a.login();

	    if (token == null) {
				LoggerFactory.getLogger(App.class).
					warn("could not aquire auth token, exiting.");
				return;
			}


	    System.out.println(token);

	    Logger log = LoggerFactory.getLogger(App.class);

	    log.info(token);
	    
		JwtParser fwtparser = new JwtParser();
		
		try {
			Claims claims = fwtparser.parseJWT(token);
			log.info("ID: " + claims.getId());
			log.info("Subject (User id): " + claims.getSubject());
			log.info("Expiration: " + claims.getExpiration());
			log.info("Audience: " + claims.get("aud"));

			// Get some user data
			log.info("Username: " + claims.get("preferred_username"));
			log.info("Name: " + claims.get("name"));
			log.info("E-Mail: " + claims.get("email"));

			log.info("Component realm: " + claims.get("aud"));
			
		} catch (ExpiredJwtException e) {
			System.err.println(e.getMessage());
		}	    

	    String userId = "0dfc01f7-a234-4cbc-8e70-7ae361127dd4";
		
		// user id of organicity/fbuether
	    List<String> roles = a.getUserRoles(userId);
	    if (roles != null) {
	      log.info("got roles:");
	      for(String role : roles) {
	        log.info("Role " + role);
	      }
	    }
	    
	    // a.setUserRole(userId, "scenarios:admin");
	    
	}
	
  public static void main( String[] args )
  {
    // up the logging level.
    ((ch.qos.logback.classic.Logger)LoggerFactory.
     getLogger(Logger.ROOT_LOGGER_NAME)).
      setLevel(ch.qos.logback.classic.Level.TRACE);

    String auth = args.length > 0
			? args[0]
			: "<INSERT TOKEN HERE>";

    exampleGetRoles(auth);
  }
}
