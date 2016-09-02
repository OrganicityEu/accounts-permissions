
package eu.organicity.accounts.permissions;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.WeakHashMap;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.organicity.JwtParser;
import io.jsonwebtoken.Claims;


/**
 * Organicity Accounts - Permission Component
 *
 * This class facilitates easy access to read and manipulate the assigned
 * roles (i.e. permissions) of users in Organicity.
 */
public class Accounts
{
  private static Logger log = LoggerFactory.getLogger(Accounts.class);

  //private static String host = "https://accounts.organicity.eu";
  private static String host = "https://accounts.organicity.eu";
  private static String baseUrl = host + "/admin/";
  private static String tokenUrl = host +  "/realms/organicity/protocol/openid-connect/token";

  private Client client = null;

  protected Accounts()
  {
    // This constructor only inhibits external new-construction.
  }

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
    //Client c = ClientBuilder.newClient();
	  ClientConfig config = new ClientConfig();
	  config.property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true);
	  Client c = ClientBuilder.newClient(config);	  

    c.register(
      new ClientResponseFilter() {
        // private Logger log = LoggerFactory.getLogger("permissions.request-log");

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
            if (reqEntity instanceof Form) {
              Accounts.log.trace("Form: " + ((Form)reqEntity).asMap().toString());
            }
            else {
              Accounts.log.trace(reqEntity.toString());
            }
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

  /**
   * Checks if the current login token is still valid, and if it is not,
   * refreshes it by performing a new login.
   */
  private void refreshLoginIfRequired()
  {
    String token = this.authToken;
    if (token == null) {
      this.refreshLogin();
      return;
    }

    Claims c = null;
    try {
      c = (new JwtParser()).parseJWT(token);
    }
    catch (Exception e) {
      this.refreshLogin();
      return;
    }

    if (c == null) {
      this.refreshLogin();
      return;
    }

    // If the current token expires in the next 30 seconds, refresh.
    Calendar in30seconds = Calendar.getInstance();
    in30seconds.add(Calendar.SECOND, 30);
    Date expires = null;
    expires = c.getExpiration();

    Accounts.log.trace("Token Expiration check: Token expires " +
      expires.toString());

    if (expires != null && expires.before(in30seconds.getTime())) {
      this.refreshLogin();
    }
  }

  private void refreshLogin()
  {
    if (this.basicAuthString != null) {
      this.loginBasicAuth(this.basicAuthString);
    }
    else {
      Accounts.log.warn("No login mechanism available.");
    }
  }



  /**
   * Determines the list of roles that are assigned to the given user.
   * This returns all realm-level roles assigned, but no client roles.
   *
   * @param userId The user id, as given by the "sub" field in the auth token.
   * @return The list of roles assigned to the user.
   */
  public List<String> getUserRoles(String userId) {
    return this.getUserRoles(userId, null, false);
  }

  /**
   * Determines the list of roles that are assigned to the given user.
   * This always returns all realm-level roles assigned, and if a non-null
   * clientName is given, also returns the list of roles for that client.
   *
   * @param userId The user id, as given by the "sub" field in the auth token.
   * @param clientName The client for which roles are requested
   * @return The list of roles assigned to the user.
   */
  public List<String> getUserRoles(String userId, String clientName)
  {
    return this.getUserRoles(userId, clientName, false);
  }

  /**
   * Determines the list of roles that are assigned to the given user.
   * The list of roles returned depends on the third parameter onlyClient: If
   * this value is false, all realm-level roles assigned to the userId are
   * returned, and if a clientName is given, all roles specific to that client
   * as well. If onlyClient is true, this call only returns permissions for
   * clientName, or if clientName is null, no roles at all.
   *
   * @param userId The user id, as given by the "sub" field in the auth token.
   * @param clientName The client for which roles are requested.
   * @param onlyClient True if only client-level permissions should be returned.
   * @return The list of roles assigned to the user.
   */
  public List<String> getUserRoles(String userId, String clientName, Boolean onlyClient)
  {
    List<String> roles = new Vector<String>();

    if (!onlyClient) {
      // fetch realm-level role mappings of this user
      Response res = this.getClient().
        target(Accounts.baseUrl +
          "realms/organicity/users/{id}/role-mappings/realm/composite").
        resolveTemplate("id", userId).
        request().
        header("Authorization", "Bearer " + this.getAuthToken()).
        buildGet().
        invoke();

      if (res.hasEntity()) {
        String body = res.readEntity(String.class);
        Accounts.log.trace("GetUserRoles: " + body);

        if (res.getStatus() == 200) {
          JSONArray roleMappings = new JSONArray(body);

          for(Object mappingObj : roleMappings) {
            JSONObject mapping = (JSONObject)mappingObj;

            if (mapping != null) {
              String roleId = mapping.getString("id");
              String roleName = mapping.getString("name");

              if (roleId != null && roleName != null) {
                roles.add(roleName);
                this.roleNameToId.put(roleName, roleId);
              }
            }
          }
        }
        else {
          Accounts.log.warn("Could not read realm-level roles for user \"" +
            userId + "\".");
        }
      }
      else {
        Accounts.log.warn("Did not receive realm-level roles for user.");
        return null;
      }
    }

    // if no client roles are requested, exit now.
    if (clientName == null) {
      return roles;
    }

    String clientId = this.getClientIdByName(clientName);
    if (clientId == null) {
      Accounts.log.warn("Could not get clientId for clientName \"" +
        clientName + "\".");
      return roles;
    }

    // fetch role mappings for client
    Response res = this.getClient().
      target(Accounts.baseUrl +
        "realms/organicity/users/{id}/role-mappings/clients/{client}/composite").
      resolveTemplate("id", userId).
      resolveTemplate("client", clientId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildGet().
      invoke();

    if (res.hasEntity()) {
      String body = res.readEntity(String.class);
      Accounts.log.trace("GetUserRoles: " + body);

      if (res.getStatus() == 200) {
        JSONArray roleMappings = new JSONArray(body);

        for(Object mappingObj : roleMappings) {
          JSONObject mapping = (JSONObject)mappingObj;

          if (mapping != null) {
            String roleId = mapping.getString("id");
            String roleName = mapping.getString("name");

            if (roleId != null && roleName != null) {
              roles.add(clientName + ":" + roleName);
              this.roleNameToId.put(clientName + ":" + roleName, roleId);
            }
          }
        }
      }
      else {
        Accounts.log.warn("Could not read client-level roles for user." +
          userId);
      }
    }
    else {
      Accounts.log.warn("Did not receive client-level roles for user.");
      return null;
    }

    return roles;
  }


  public Boolean isRealmRole(String role)
  {
    // A role belongs to a realm if it does not contain a :
    return !role.contains(":");
  }

  private String getClientOfRole(String role)
  {
    return this.isRealmRole(role)
      ? ""
      : role.substring(0, role.indexOf(':'));
  }

  private String getNameOfRole(String role)
  {
    return this.isRealmRole(role)
      ? role
      : role.substring(role.indexOf(':') + 1);
  }

  private HashMap<String,String> clientNameToId = new HashMap<String, String>();

  private WeakHashMap<String, String> roleNameToId =
    new WeakHashMap<String, String>();


  private String getClientIdByName(String clientId)
  {
    if (!this.clientNameToId.containsKey(clientId)) {
      Response res = this.getClient().
        target(Accounts.baseUrl + "realms/organicity/clients").
        resolveTemplate("id", clientId).
        request().
        header("Authorization", "Bearer " + this.getAuthToken()).
        buildGet().
        invoke();

      if (res.getStatus() == 200) {
        JSONArray clients = new JSONArray(res.readEntity(String.class));
        for(Object clientObj : clients) {
          JSONObject client = (JSONObject)clientObj;
          if (client != null) {
            String currId = client.getString("id");
            String currClientId = client.getString("clientId");
            if (currId != null && currClientId != null) {
              this.clientNameToId.put(currClientId, currId);
            }
          }
        }

        if (!this.clientNameToId.containsKey(clientId)) {
          this.clientNameToId.put(clientId, null);
        }
      }
      else {
        Accounts.log.info("Could not get client with id " + clientId);
        return null;
      }
    }

    return this.clientNameToId.get(clientId);
  }

  private String getRoleIdByName(String roleName)
  {
    String target = Accounts.baseUrl + (this.isRealmRole(roleName)
      ? "realms/organicity/roles/{role-name}"
      : "realms/organicity/clients/{id}/roles/{role-name}");

    String clientId = this.isRealmRole(roleName)
      ? ""
      : this.getClientIdByName(this.getClientOfRole(roleName));

    if (clientId == null) {
      Accounts.log.warn("Could not determine clientId for role " + roleName);
      return null;
    }

    if (!this.roleNameToId.containsKey(roleName)) {
      Response res = this.getClient().
        target(target).
        resolveTemplate("id", clientId).
        resolveTemplate("role-name", this.getNameOfRole(roleName)).
        request().
        header("Authorization", "Bearer " + this.getAuthToken()).
        buildGet().
        invoke();

      if (res.getStatus() == 200) {
        JSONObject role = new JSONObject(res.readEntity(String.class));
        String currId = role.getString("id");
        String currName = role.getString("name");
        if (currId != null && currName != null &&
          this.getNameOfRole(roleName).equals(currName)) {
          this.roleNameToId.put(roleName, currId);
        }

        if (!this.roleNameToId.containsKey(roleName)) {
          this.roleNameToId.put(roleName, null);
        }
      }
      else {
        Accounts.log.trace("Could not get role with name " + roleName);
        return null;
      }
    }

    return this.roleNameToId.get(roleName);
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
      ? "realms/organicity/users/{userId}/role-mappings/realm"
      : "realms/organicity/users/{userId}/role-mappings/clients/{client}");

    String clientId = this.isRealmRole(role)
      ? ""
      : this.getClientIdByName(this.getClientOfRole(role));

    String roleId = this.getRoleIdByName(role);
    if (roleId == null) {
      Accounts.log.warn("could not assign role " + role + ", id not found.");
      return false;
    }

    JSONArray jsonRole = new JSONArray().
      put(new JSONObject().
        put("name", this.getNameOfRole(role)).
        put("id", roleId));

    Response res = this.getClient().
      target(target).
      resolveTemplate("userId", userId).
      resolveTemplate("client", clientId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildPost(Entity.json(jsonRole.toString())).
      invoke();

    Accounts.log.trace("setUserRole " + res.getStatus() + ": " +
      res.readEntity(String.class));

    return res.getStatus() == 204;
  }


  /**
   * Queries for a list of user identifiers.
   * This funtion returns users in a paginated way, that is, from the whole
   * big list of all users, it returns the first 50 users. For more users after
   * that, please use the parametrised versions of this function.
   *
   * @return A list of user identifier records.
   */
  public List<UserIdentifier> getUsers()
  {
    return this.getUsers(0, 50);
  }

  /**
   * Queries for a list of user identifiers.
   * This funtion returns users in a paginated way, that is, from the whole
   * big list of all users, it skips the first <offset> users, and returns the
   * next 50 users from there on.
   *
   * @param offset The offset in the list of users, i.e. the number of users
   * to skip.
   * @return A list of user identifier records.
   */
  public List<UserIdentifier> getUsers(int offset)
  {
    return this.getUsers(offset, 50);
  }

  /**
   * Queries for a list of user identifiers.
   * This funtion returns users in a paginated way, that is, from the whole
   * big list of all users, it skips the first <offset> users, and returns the
   * next <count> users from there on.
   *
   * @param offset The offset in the list of users, i.e. the number of users
   * to skip.
   * @param count The count of users to return, maxium of 50.
   * @return A list of user identifier records, or `null` if the parameters are
   * out of range.
   */
  public List<UserIdentifier> getUsers(int offset, int count)
  {
    List<UserIdentifier> users = new Vector<UserIdentifier>();

    if (offset < 0 || count <= 0 || count > 50) {
      return null;
    }

    Response res = this.getClient().
      target(Accounts.baseUrl + "realms/organicity/users").
      queryParam("first", offset).
      queryParam("max", count).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildGet().
      invoke();

    if (res.hasEntity() && res.getStatus() == 200)
    {
      String body = res.readEntity(String.class);
      Accounts.log.trace("GetUsers: " + body);

      JSONArray userList = new JSONArray(body);
      for (Object userObj : userList) {
        JSONObject user = (JSONObject)userObj;

        if (user != null) {
          users.add(
            new UserIdentifier(user.getString("id"),
              user.getString("username")));
        }
      }
    }
    else {
      Accounts.log.warn("Could not fetch a list of users. (" + res.getStatus() +
        ")");
      return null;
    }

    return users;
  }


  private String authToken = null;

  public String getAuthToken()
  {
    this.refreshLoginIfRequired();

    if (this.authToken == null) {
      throw new Error("Accounts cannot login, no Authentication Token could " +
        "be acquired.");
    }

    return this.authToken;
  }

  private String basicAuthString = null;

  /**
   * Greates a new Organicity Accounts interface which performs login using
   * Basic Authentication.
   *
   * @param basicAuthString The string used for HTTP Basic Authentication (e.g.
   *   username:password base64 encoded).
   * @return The new Organicity Accounts interface object.
   */
  public static Accounts withBasicAuth(String basicAuthString)
  {
    Accounts a = new Accounts();
    a.basicAuthString = basicAuthString;
    return a;
  }

  public String loginBasicAuth(String basicAuthString)
  {
    // Connects with the accounts-permissions service account.
	  Accounts.log.info("Logging in with accounts-permissions.");

    if (basicAuthString == null) {
      Accounts.log.error("No auth token for login supplied. Canceling login.");
      return null;
    }

    this.basicAuthString = basicAuthString;

    Response res = this.getClient().target(Accounts.tokenUrl).
      request().
      header("Authorization", "Basic " + basicAuthString).
      buildPost(Entity.form(new Form("grant_type", "client_credentials"))).
      invoke();


    if (res.hasEntity()) {
      String body = res.readEntity(String.class);
      Accounts.log.info("Reply: " + res.getStatus());
      Accounts.log.trace("Body: " + body);

      if (res.getStatus() == 200) {
        JSONObject reply = new JSONObject(body);
        String token = reply.getString("access_token");
        Accounts.log.trace("token: " + token);
        this.authToken = token;
        return token;
      }
      else {
        Accounts.log.warn("login was not successful. Reply: HTTP " +
          res.getStatus());
        Accounts.log.warn("Body: " + body);
        return null;
      }
    }
    else {
      Accounts.log.trace("login reply has no content.");
      return null;
    }
  }

  public Boolean removeUserRole(String userId, String roleName)
  {
    String target = Accounts.baseUrl + (this.isRealmRole(roleName)
      ? "realms/organicity/users/{userId}/role-mappings/realm"
      : "realms/organicity/users/{userId}/role-mappings/clients/{client}");

    String clientId = this.isRealmRole(roleName)
      ? ""
      : this.getClientIdByName(this.getClientOfRole(roleName));

    String roleId = this.getRoleIdByName(roleName);
    if (roleId == null) {
      Accounts.log.warn("could not remove role " + roleName + ", id not found.");
      return false;
    }

    JSONArray jsonRole = new JSONArray().
      put(new JSONObject().
        put("name", this.getNameOfRole(roleName)).
        put("id", roleId));

    Response res = this.getClient().
      target(target).
      resolveTemplate("userId", userId).
      resolveTemplate("client", clientId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      method("DELETE", Entity.json(jsonRole.toString()));

    Accounts.log.trace("setUserRole " + res.getStatus() + ": " +
      res.readEntity(String.class));

    return res.getStatus() == 204;
  }
}
