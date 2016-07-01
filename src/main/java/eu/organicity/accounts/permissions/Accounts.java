
package eu.organicity.accounts.permissions;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientRequestContext;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Form;
import javax.ws.rs.client.Entity;
import java.util.*;
import java.io.IOException;


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
    ClientConfig config = new ClientConfig();
    config.property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true);
    Client c = ClientBuilder.newClient(config);

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

    Accounts.log.trace("Body: " + body);

    return body;
  }

  /**
   * Determines the list of roles that are assigned to the given user.
   * This returns all realm-level roles assigned, but no client roles.
   *
   * @param userId The user id, as given by the "sub" field in the auth token.
   * @return The list of roles assigned to the user.
   */
  public List<String> getUserRoles(String userId) {
    return this.getUserRoles(userId, null);
  }

  /**
   * Determines the list of roles that are assigned to the given user.
   * This always returns all realm-level roles assigned, and if a non-null
   * clientId is given, also returns the list of roles for that client.
   *
   * @param userId The user id, as given by the "sub" field in the auth token.
   * @param clientId The client for which roles are requested
   * @return The list of roles assigned to the user.
   */
  public List<String> getUserRoles(String userId, String clientId)
  {
    // fetch realm-level role mappings of this user
    Response res = this.getClient().
      target(Accounts.baseUrl +
        "realms/organicity/users/{id}/role-mappings/realm/composite").
      resolveTemplate("id", userId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildGet().
      invoke();

    List<String> roles = new Vector<String>();

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
        Accounts.log.warn("Could not read realm-level roles for user." +
          userId);
      }
    }
    else {
      Accounts.log.warn("Did not receive realm-level roles for user.");
      return null;
    }

    // if no client roles are requested, exit now.
    if (clientId == null) {
      return roles;
    }

    // fetch role mappings for client
    res = this.getClient().
      target(Accounts.baseUrl +
        "realms/organicity/users/{id}/role-mappings/clients/{client}/composite").
      resolveTemplate("id", userId).
      resolveTemplate("client", this.getClientIdByName(clientId)).
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
              roles.add(clientId + ":" + roleName);
              this.roleNameToId.put(clientId + ":" + roleName, roleId);
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


  private Boolean isRealmRole(String role)
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
        Accounts.log.trace("Could not get client with id " + clientId);
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


  private String authToken = null;

  protected String getAuthToken()
  {
    if (this.authToken == null) {
      throw new Error("Accounts cannot login, no Basic Auth given.");
    }

    return this.authToken;
  }

  /**
   * Acquires a login token for this tool.
   *
   * FIXME: This currently uses the client/secret login mechanism; replace
   * with public/private key login.
   * @param basicAuthString The string used for HTTP Basic Authentication (e.g.
   *   username:password base64encoded).
   * @return The authentication token to be used by this client.
   */
  public String login(String basicAuthString)
  {
    // Connects with the accounts-permissions service account.
    Accounts.log.info("Logging in with accounts-permissions.");

    if (basicAuthString == null) {
      Accounts.log.error("No auth token for login supplied. Canceling login.");
      return null;
    }

    String url = "https://accounts.organicity.eu/realms/organicity/" +
      "protocol/openid-connect/token";


    Response res = this.getClient().target(url).
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
