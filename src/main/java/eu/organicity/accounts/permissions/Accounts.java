
package eu.organicity.accounts.permissions;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Form;
import javax.ws.rs.client.Entity;
import java.util.Map;
import java.util.List;
import java.util.Vector;
import java.io.IOException;
import java.util.Scanner;


import org.json.JSONObject;
import org.json.JSONArray;


/**
 * Organicity Accounts - Permission Component
 *
 * This class facilitates easy access to read and manipulate the assigned
 * roles (i.e. permissions) of users in Organicity.
 */
public class Accounts
{
  private static Logger log = LoggerFactory.getLogger(Accounts.class);

  private static String baseUrl = "https://accounts.organicity.eu/admin/";

  private String auth = null;

  public Accounts(String auth) {
	  this.auth = auth;
  }

  private Client client = null;

  /**
   * Creates a new JAX RS Client as the base for performing HTTP requests.
   * @return A new created client, or null on error.
   */
  protected Client getClient()
  {
    if (this.client == null) {
      this.client = this.createClient();
    }

    return this.client;
  }

  private Client createClient()
  {
    Client c = ClientBuilder.newClient();

    c.register(
      new ClientResponseFilter() {
        private Logger log = LoggerFactory.getLogger(
          "permissions.request-log");

        private String join(String sep, List<Object> el) {
          String resp = "";

          for (int i = 0; i < el.size(); i++) {
            resp += el.get(i).toString();

            if (i + 1 < el.size()) {
              resp += sep;
            }
          }

          return resp;
        }

        private String joinStrings(String sep, List<String> el) {
          String resp = "";

          for (int i = 0; i < el.size(); i++) {
            resp += el.get(i);

            if (i + 1 < el.size()) {
              resp += sep;
            }
          }

          return resp;
        }

        public void filter(ClientRequestContext req,
                           ClientResponseContext res)
          throws IOException {

          Accounts.log.trace("Executing Request:");
          Accounts.log.trace(req.getMethod() + " " +
                         req.getUri().toString());
          Map<String, List<Object>> headers = req.getHeaders();
          for (Map.Entry<String, List<Object>> header : headers.entrySet()) {
            Accounts.log.trace(header.getKey() + ": " +
                           this.join(", ", header.getValue()));
          }

          Object reqEntity = req.getEntity();
          if (reqEntity != null) {
            Accounts.log.trace("");
            Accounts.log.trace(reqEntity.toString());
          }

          Accounts.log.trace("");

          Accounts.log.trace("Response:");
          Accounts.log.trace("HTTP " + res.getStatus());
          Map<String, List<String>> resHeaders = res.getHeaders();
          for (Map.Entry<String, List<String>> header : resHeaders.entrySet()) {
            Accounts.log.trace(header.getKey() + ": " +
                           this.joinStrings(", ", header.getValue()));
          }

          Accounts.log.trace("skip printing body...");
          // if (res.hasEntity()) {
          //   Scanner s = new Scanner(res.getEntityStream()).useDelimiter("\\A");
          //   String resEntity = s.hasNext() ? s.next() : "";

          //   Accounts.log.trace("");
          //   Accounts.log.trace(resEntity);
          // }

          Accounts.log.trace("");
        }
      }
    );

    return c;
  }

  private String demonstratePerformHttpRequest(String userId)
  {
    Accounts.log.info("Requesting user roles for " + userId);

    Client c = ClientBuilder.newClient();

    WebTarget t = c.target(Accounts.baseUrl + "realms/organicity/users/" + userId +
                           "/role-mappings/realm");

    Builder b = t.request();

    Invocation i = b.buildGet();

    Response r = i.invoke();


    MultivaluedMap<String, Object> headers = r.getHeaders();

    Accounts.log.info("Reply Status Code: " + r.getStatus());


    for (Map.Entry<String, List<Object>> entry : headers.entrySet()) {
      Accounts.log.info("Header: " + entry.getKey() + ":");

      for (Object value: entry.getValue()) {
        String valueString = value.toString();
        Accounts.log.info(valueString);
      }
    }


    String body = r.readEntity(String.class);

    Accounts.log.info("Body: " + body);

    return body;
  }

  /**
   * Determines the list of roles that are assigned to the given user.
   * @param userId The user id, as given by the "sub" field in the auth token.
   * @return The list of roles assigned to the user.
     */
  public List<String> getUserRoles(String userId)
  {
    Response res = this.getClient().
      target(Accounts.baseUrl + "realms/organicity/users/{id}/role-mappings").
      resolveTemplate("id", userId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildGet().
      invoke();


    if (res.hasEntity()) {
      String body = res.readEntity(String.class);

      Accounts.log.trace("GetUserRoles: " + body);


      List<String> roles = new Vector<String>();
      return roles;
    }
    else {
      return null;
    }
  }


  private Boolean isRealmRole(String role)
  {
    // A role belongs to a realm if it does not contain a :
    return !role.contains(":");
  }

  private String getClientOfRole(String role)
  {
    return this.isRealmRole(role)
      ? null
      : role.substring(0, role.indexOf(':'));
  }

  private String getNameOfRole(String role)
  {
    return this.isRealmRole(role)
      ? role
      : role.substring(role.indexOf(':'));
  }

  /**
   * Assigns a role to a user.
   * @param userId The user id, as given by the subject field in the auth token.
   * @param role the named role to be assigned to the user.
   * @return true if the role has been successfully assigned.
   */
  public Boolean setUserRole(String userId, String role)
  {
    String target = Accounts.baseUrl + (this.isRealmRole(role)
      ? "/realms/organicity/users/{userId}/role-mappings/realm"
      : "/realms/organicity/users/{userId}/role-mappings/clients/{client}");

    JSONArray jsonRole = new JSONArray().
      put(new JSONObject().
        put("name", this.getNameOfRole(role)));

    Response res = this.getClient().
      target(target).
      resolveTemplate("userId", userId).
      resolveTemplate("client", this.getClientOfRole(role)).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildPost(Entity.json(jsonRole.toString())).
      invoke();

    return res.getStatus() == 200;
  }


  private String authToken = null;

  protected String getAuthToken()
  {
    if (this.authToken == null) {
      this.login();
    }

    return this.authToken;
  }

  /**
   * Acquires a login token for this tool.
   *
   * FIXME: This currently uses the client/secret login mechanism; replace
   * with public/private key login.
   * @return The authentication token to be used by this client.
   */
  public String login()
  {
    // Connects with the accounts-permissions service account.
    Accounts.log.info("Logging in with accounts-permissions.");

    Client c = this.getClient();


    String url = "https://accounts.organicity.eu/realms/organicity/" +
      "protocol/openid-connect/token";


    Response res = c.target(url).
      request().
      header("Authorization", this.auth).
      buildPost(Entity.form(new Form("grant_type", "client_credentials"))).
      invoke();


    if (res.hasEntity()) {
      String body = res.readEntity(String.class);
      Accounts.log.info("Reply: " + res.getStatus());
      Accounts.log.info("Body: " + body);

      JSONObject reply = new JSONObject(body);

      Accounts.log.trace("token: " + reply.toString());


      String token = reply.getString("access_token");

      this.authToken = token;
      return token;
    }
    else {
      Accounts.log.trace("login reply has no content.");
      return null;
    }
  }
}
