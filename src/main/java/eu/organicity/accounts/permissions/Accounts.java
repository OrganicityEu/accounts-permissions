
package eu.organicity.accounts.permissions;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.WeakHashMap;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

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
  private static String realm = "organicity";
  private static String tokenUrl = host + "/realms/{realm}/protocol/openid-connect/token";

  private Client client = null;
  private MySqlConfig mysqlconfig = null;

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
	  ClientConfig config = new ClientConfig();
	  config.property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true);
	  Client c = ClientBuilder.newClient(config);

    c.register(
      new ClientResponseFilter() {
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
              Accounts.log.trace("Form: " +
                ((Form)reqEntity).asMap().toString());
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
          //   Scanner s = new Scanner(res.getEntityStream()).
          //     useDelimiter("\\A");
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
    String token = Accounts.token;
    if (token == null) {
      Accounts.log.debug("Token null. Get a new token!");
      this.refreshLogin();
      return;
    }

    Claims c = null;
    try {
      c = (new JwtParser()).parseJWT(token);
    }
    catch (Exception e) {
      Accounts.log.debug(e.getMessage() + ". Get a new token!");
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

    if (expires != null && expires.before(in30seconds.getTime())) {
      Accounts.log.debug("Token expired. Get a new token!");
      this.refreshLogin();
    } else {
    	Accounts.log.debug("Token valid. Expires at " + expires.toString());
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
  public List<String> getUserRoles(String userId, String clientName,
    boolean onlyClient)
  {
    List<String> roles = new Vector<String>();

    if (!onlyClient) {
      // fetch realm-level role mappings of this user
      Accounts.log.debug("fetch realm-level role mappings - START");

      Response res = this.getClient().
        target(Accounts.baseUrl +
          "realms/{realm}/users/{id}/role-mappings/realm/composite").
        resolveTemplate("realm", realm).
        resolveTemplate("id", userId).
        request().
        header("Authorization", "Bearer " + this.getAuthToken()).
        buildGet().
        invoke();

      Accounts.log.debug("fetch realm-level role mappings - END");

      if (res.hasEntity()) {
        String body = res.readEntity(String.class);
        Accounts.log.debug("GetUserRoles: " + body);

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

    Accounts.log.debug("Get role mapping");

    // fetch role mappings for client
    Response res = this.getClient().
      target(Accounts.baseUrl +
        "realms/{realm}/users/{id}/role-mappings/clients/{client}/composite").
      resolveTemplate("realm", realm).
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


  public boolean isRealmRole(String role)
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
	Accounts.log.debug("getClientIdByName");

    if (!this.clientNameToId.containsKey(clientId)) {
      Response res = this.getClient().
        target(Accounts.baseUrl + "realms/{realm}/clients").
        resolveTemplate("realm", realm).
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
      ? "realms/{realm}/roles/{role-name}"
      : "realms/{realm}/clients/{id}/roles/{role-name}");

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
        resolveTemplate("realm", realm).
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
   * @param role the named role to be assigned to the user. This role is always
   * global, i.e. has no further specification (like e.g. an experiment).
   * @return true if the role has been successfully assigned.
   */
  public boolean setUserRole(String userId, String role)
  {
    String target = Accounts.baseUrl + (this.isRealmRole(role)
      ? "realms/organicity/users/{id}/role-mappings/realm"
      : "realms/organicity/users/{id}/role-mappings/clients/{client}");

    return this.setUserOrClientRole(target, userId, role);
  }

  private boolean setUserOrClientRole(String target, String id, String role)
  {
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
      resolveTemplate("realm", realm).
      resolveTemplate("id", id).
      resolveTemplate("client", clientId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildPost(Entity.json(jsonRole.toString())).
      invoke();

    Accounts.log.trace("setUserRole " + res.getStatus() + ": " +
      res.readEntity(String.class));

    return res.getStatus() == 204;
  }

  public boolean setClientScopeRole(String clientName, String role)
  {
    String target = Accounts.baseUrl + (this.isRealmRole(role)
      ? "realms/{realm}/clients/{id}/scope-mappings/realm"
      : "realms/{realm}/clients/{id}/scope-mappings/clients/{client}");

    String clientId = this.getClientIdByName(clientName);
    if (clientId == null) {
      Accounts.log.error("setClientRole: Could not find clientId.");
      return false;
    }

    return this.setUserOrClientRole(target, clientId, role);
  }


  private String roleToLinearName(Role role)
  {
    String fullName = role.Name;

    if (role.Experiment != null) {
      fullName += "?experiment";
    }

    return fullName;
  }

  private String roleToConcreteName(Role role)
  {
    String fullName = role.Name;

    if (role.Experiment != null) {
      fullName += "?experiment=" + role.Experiment;
    }

    return fullName;
  }

  /**
   * Assign a role to a user.
   * @param userId The user id, as given by the subject field in the auth token.
   * @param role The role to be assigned, potentially containing further
   * dimensions to concretise the role.
   * @return true if the role has been successfully assigned.
   */
  public boolean setUserRole(String userId, Role role)
  {
    String linearName = this.roleToLinearName(role);
    String linearId = this.getRoleIdByName(linearName);
    if (linearId == null) {
      Accounts.log.warn("The role " + linearName + " does not exist.");
      return false;
    }

    String concreteName = this.roleToConcreteName(role);
    if (!this.isPlainRole(role)) {
      String concreteId = this.getRoleIdByName(concreteName);
      if (concreteId == null) {
        if (!this.createRole(concreteName)) {
          Accounts.log.warn("Could not create concrete role " + concreteName
            + ".");
          return false;
        }
      }
    }

    return this.setUserRole(userId, concreteName);
  }

  private boolean isPlainRole(Role role) {
    return role.Experiment == null;
  }

  public boolean createRole(String role)
  {
    String target = Accounts.baseUrl + (this.isRealmRole(role)
      ? "realms/{realm}/roles"
      : "realms/{realm}/clients/{id}/roles");

    String clientId = this.isRealmRole(role)
      ? ""
      : this.getClientIdByName(this.getClientOfRole(role));

    if (clientId == null) {
      Accounts.log.warn("Could not determine clientId for role " + role);
      return false;
    }

    JSONObject jsonRole = new JSONObject().
      put("name", this.getNameOfRole(role));

    if (!this.roleNameToId.containsKey(role)) {
      Response res = this.getClient().
        target(target).
        resolveTemplate("realm", realm).
        resolveTemplate("id", clientId).
        request().
        header("Authorization", "Bearer " + this.getAuthToken()).
        buildPost(Entity.json(jsonRole.toString())).
        invoke();

      if (res.getStatus() != 200) {
        Accounts.log.warn("Server unwilling to create role " + role + ".");
        return false;
      }
    }

    return true;
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
    if (offset < 0 || count <= 0 || count > 50) {
      return null;
    }

    Response res = this.getClient().
      target(Accounts.baseUrl + "realms/{realm}/users").
      resolveTemplate("realm", realm).
      queryParam("first", offset).
      queryParam("max", count).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildGet().
      invoke();

    return this.getUsersFromResponse(res);
  }

  public UserIdentifier getUserById(String id)
  {
	JSONObject jsonUser = getUserByIdJSON(id);
	if(jsonUser == null) {
		return null;
	}
    return new UserIdentifier(jsonUser);
  }

  private JSONObject getUserByIdJSON(String id)
  {
    Response res = this.getClient().
      target(Accounts.baseUrl + "realms/{realm}/users/" + id).
      resolveTemplate("realm", realm).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildGet().
      invoke();

    if (res.hasEntity() && res.getStatus() == 200)
    {
      String body = res.readEntity(String.class);
      return new JSONObject(body);
    }
    return null;
  }

  public void updateUserById(String id, UserIdentifier ui) throws Exception
  {
	// Get the user as KeyCloak JSON-format
	JSONObject jsonUser = getUserByIdJSON(id);
	if(jsonUser == null) {
		System.out.println("ERROR 1");
	    throw new Exception("User cannot be found!");
	}

	if(id == null || !id.equals(ui.getId())) {
		System.out.println("ERROR 2");
		throw new Exception("Given id and id inside JSON are not the same.");
	}

	// Modify the JSON
	jsonUser.put("email", ui.getEmail());
	jsonUser.put("firstName", ui.getFirstName());
	jsonUser.put("lastName", ui.getLastName());
	jsonUser.put("username", ui.getName());

	// Update the user with the modified JSON
    Response res = this.getClient().
      target(Accounts.baseUrl + "realms/{realm}/users/" + id).
      resolveTemplate("realm", realm).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildPut(Entity.json(jsonUser.toString())).
      invoke();

    if (res.getStatus() == 204) {
    	Accounts.log.info("User update successful!");
    } else {
    	Accounts.log.error("User update fails!");
		System.out.println("ERROR 3");
    	if (res.hasEntity())
    	{
    		String body = res.readEntity(String.class);
    		JSONObject error = new JSONObject(body);
    		if(error.has("errorMessage")) {
    			throw new Exception(error.getString("errorMessage"));
    		} else {
    			throw new Exception("Unknown error");
    		}
    	}
    }
  }

  private List<UserIdentifier> getUsersFromResponse(Response res)
  {
	  List<JSONObject> usersJson = getUsersFromResponseAsJson(res);
	  if(usersJson == null) {
		  return null;
	  }

	  // Convert from JSONObject to UserIdentifier
	  List<UserIdentifier> users = new Vector<UserIdentifier>();
	  for (JSONObject user : usersJson) {
		  users.add(new UserIdentifier(user));
	  }

	  return users;
  }

  private List<JSONObject> getUsersFromResponseAsJson(Response res)
  {
    List<JSONObject> users = new Vector<JSONObject>();

    if (res.hasEntity() && res.getStatus() == 200)
    {
      String body = res.readEntity(String.class);
      Accounts.log.trace("GetUsersFromResponse: " + body);

      JSONArray userList = new JSONArray(body);
      for (Object userObj : userList) {
        JSONObject user = (JSONObject)userObj;

        if (user != null) {
          users.add(user);
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
  
  
  public String getAuthToken()
  {
    this.refreshLoginIfRequired();

    if (Accounts.token == null) {
      throw new Error("Accounts cannot login, no Authentication Token could " +
        "be acquired.");
    }
    return Accounts.token;
  }

  private String basicAuthString = null;
  public static String token = null;

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

  public static Accounts withBasicAuth(String basicAuthString, MySqlConfig mysqlConfig)
  {
    Accounts a = new Accounts();
    a.basicAuthString = basicAuthString;
    a.mysqlconfig = mysqlConfig;
    return a;
  }

  protected void loginBasicAuth(String basicAuthString)
  {
	// Connects with the accounts-permissions service account.
	Accounts.log.info("Logging in with accounts-permissions.");
	
	if (basicAuthString == null) {
		Accounts.log.error("No auth token for login supplied. Canceling login.");
		Accounts.token = null;
		return;
	}
	
	this.basicAuthString = basicAuthString;
	
	Response res = this.getClient().target(Accounts.tokenUrl).
	    resolveTemplate("realm", realm).
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
			Accounts.token = token;
			return;
		}
		else {
			Accounts.log.warn("login was not successful. Reply: HTTP " +
					res.getStatus());
			Accounts.log.warn("Body: " + body);
			Accounts.token = null;
			return;
		}
	}
	else {
		Accounts.log.trace("login reply has no content.");
		Accounts.token = null;
		return;
	}
  }

  public boolean removeUserRole(String userId, String roleName)
  {
    String target = Accounts.baseUrl + (this.isRealmRole(roleName)
      ? "realms/{realm}/users/{userId}/role-mappings/realm"
      : "realms/{realm}/users/{userId}/role-mappings/clients/{client}");

    String clientId = this.isRealmRole(roleName)
      ? ""
      : this.getClientIdByName(this.getClientOfRole(roleName));

    String roleId = this.getRoleIdByName(roleName);
    if (roleId == null) {
      Accounts.log.warn(
        "could not remove role " + roleName + ", id not found.");
      return false;
    }

    JSONArray jsonRole = new JSONArray().
      put(new JSONObject().
        put("name", this.getNameOfRole(roleName)).
        put("id", roleId));

    Response res = this.getClient().
      target(target).
      resolveTemplate("realm", realm).
      resolveTemplate("userId", userId).
      resolveTemplate("client", clientId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      method("DELETE", Entity.json(jsonRole.toString()));

    Accounts.log.trace("setUserRole " + res.getStatus() + ": " +
      res.readEntity(String.class));

    return res.getStatus() == 204;
  }

  public UserIdentifier findUserByEmail(String email)
  {
    Response res = this.getClient().
      target(Accounts.baseUrl + "realms/{realm}/users").
      resolveTemplate("realm", realm).
      queryParam("email", email).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      buildGet().
      invoke();

    List<UserIdentifier> users = this.getUsersFromResponse(res);
    if (users != null && users.size() == 1) {
      return users.get(0);
    }
    else {
      return null;
    }
  }

  public boolean setFullScope(String clientName, boolean fullScope)
  {
    JSONObject clientJson = new JSONObject().
      put("fullScopeAllowed", fullScope);

    return this.updateClient(clientName, clientJson);
  }

  public List<String> getRedirectUris(String clientName)
  {
    String clientId = this.getClientIdByName(clientName);
    JSONArray urisJson = this.getRedirectUrisJson(clientId);
    Vector<String> uris = new Vector<String>();

    if (urisJson == null) {
      return null;
    }

    for(int i = 0; i < urisJson.length(); i++) {
      uris.add(urisJson.getString(i));
    }

    return uris;
  }

  private JSONArray getRedirectUrisJson(String clientId)
  {
    JSONObject body = this.getClientDescription(clientId);
    return body != null
      ? body.getJSONArray("redirectUris")
      : null;
  }

  private JSONObject getClientDescription(String clientId)
  {
    Response res = this.getClient().
      target(Accounts.baseUrl + "realms/{realm}/clients/{id}").
      resolveTemplate("realm", realm).
      resolveTemplate("id", clientId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      header("Accept", "application/json").
      buildGet().
      invoke();

    if (res.hasEntity()) {
      String body = res.readEntity(String.class);
      Accounts.log.info("Reply: " + res.getStatus());
      Accounts.log.trace("Body: " + body);

      if (res.getStatus() == 200) {
        return new JSONObject(body);
      }
      else {
        Accounts.log.warn("Fetching request URIs was not successful. Reply: HTTP " +
          res.getStatus());
        Accounts.log.warn("Body: " + body);
        return null;
      }
    }
    else {
      Accounts.log.trace("get redirect uris has no content (Status: " +
        res.getStatus() + ").");
      return null;
    }
  }

  public boolean addRedirectUri(String clientName, String newUri)
  {
    String clientId = this.getClientIdByName(clientName);

    JSONArray uris = this.getRedirectUrisJson(clientId);
    if (uris == null) {
      uris = new JSONArray();
    }

    JSONObject newUrlJson = new JSONObject().
      put("redirectUris", uris.
        put(newUri));

    return this.updateClient(clientName, newUrlJson);
  }

  public boolean removeRedirectUri(String clientName, String oldUri)
  {
    String clientId = this.getClientIdByName(clientName);

    JSONArray uris = this.getRedirectUrisJson(clientId);
    if (uris == null) {
      return false;
    }

    boolean foundUri = false;

    for(int i = 0; i < uris.length(); i++) {
      if (uris.getString(i).equals(oldUri)) {
        uris.remove(i);
        foundUri = true;
        break;
      }
    }

    if (!foundUri) {
      return false;
    }

    JSONObject clientUpdate = new JSONObject().
      put("redirectUris", uris);

    return this.updateClient(clientName, clientUpdate);
  }

  private boolean updateClient(String clientName, JSONObject clientJson) {
    String clientId = this.getClientIdByName(clientName);

    Response res = this.getClient().
      target(Accounts.baseUrl + "realms/{realm}/clients/{id}").
      resolveTemplate("realm", realm).
      resolveTemplate("id", clientId).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      header("Content-Type", "application/json").
      buildPut(Entity.json(clientJson.toString())).
      invoke();

    return res.getStatus() == 204;
  }


  public boolean IsImplicitFlowEnabled(String clientName)
  {
    String clientId = this.getClientIdByName(clientName);
    JSONObject desc = this.getClientDescription(clientId);
    return desc != null && desc.getBoolean("implicitFlowEnabled");
  }

  public boolean IsAuthCodeFlowEnabled(String clientName)
  {
    String clientId = this.getClientIdByName(clientName);
    JSONObject desc = this.getClientDescription(clientId);
    return desc != null && desc.getBoolean("standardFlowEnabled");
  }

  public boolean SetImplicitFlowEnabled(String clientName, boolean enabled)
  {
    JSONObject clientUpdate = new JSONObject().
      put("implicitFlowEnabled", enabled);
    return this.updateClient(clientName, clientUpdate);
  }

  public boolean SetAuthCodeFlowEnabled(String clientName, boolean enabled)
  {
    JSONObject clientUpdate = new JSONObject().
      put("standardFlowEnabled", enabled);
    return this.updateClient(clientName, clientUpdate);
  }

  @Deprecated
  public JSONObject registerClient(String client_name, String client_uri,
    String redirect_uri)
  {
    JSONObject jsonClient = new JSONObject().
      put("client_name", client_name).
      put("client_uri", client_uri).
      put("redirect_uris", new JSONArray().put(redirect_uri)).
      put("grant_types", new JSONArray().put("authorization_code").put("refresh_token"));

    Accounts.log.debug("jsonClient: " + jsonClient.toString());

    String url = "https://accounts.organicity.eu/realms/{realm}/clients-registrations/openid-connect";

    Response res = this.getClient().
      target(url).
      resolveTemplate("realm", realm).
      request().
      header("Authorization", "Bearer " + this.getAuthToken()).
      header("Content-Type", "application/json").
      header("Accept", "application/json").
      method("POST", Entity.json(jsonClient.toString()));

    if (res.getStatus() == 201) {
      Accounts.log.info("Client creation successful!");

      if (res.hasEntity()) {
        String body = res.readEntity(String.class);
        JSONObject reply = new JSONObject(body);
        String client_id = reply.getString("client_id");

        Accounts.log.debug("ClientID:" + client_id);

        String query = "select secret from CLIENT where client_id = '" + client_id + "';";

        Accounts.log.debug("Query:" + query);

        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
          Accounts.log.debug("Load mysql driver");
          Class.forName("com.mysql.jdbc.Driver").newInstance();
          Accounts.log.debug("Connect to DB");
          conn = DriverManager.getConnection(mysqlconfig.getConnectionUrl(),
            mysqlconfig.getConnectionUser(),
            mysqlconfig.getConnectionPassword());
          stmt = conn.createStatement();
          Accounts.log.debug("Execute Query");
          rs = stmt.executeQuery(query);
          if (rs.next()) {
            Accounts.log.debug("FOUND!");
            String secret = rs.getString("secret");
            JSONObject json = new JSONObject().
              put("client_id", client_id).
              put("secret", secret);
            Accounts.log.debug("Return JSON");
            return json;
          }
        } catch (Exception e) {
          e.printStackTrace();
          Accounts.log.info("MySQL Error!");
        } finally {
          try {
            if (rs != null) rs.close();
          } catch (SQLException e) {
            e.printStackTrace();
          }
          try {
            if (stmt != null) stmt.close();
          } catch (SQLException e) {
            e.printStackTrace();
          }
          try {
            if (conn != null) conn.close();
          } catch (SQLException e) {
            e.printStackTrace();
          }
        }
      }
    }
    else {
      Accounts.log.info("Client creation failed with status code ", res.getStatus());
    }
    return null;
  }

  public JSONObject getClient(String clientId, boolean getSecret) {
	  
	  System.out.println("Get client with clientId " + clientId);
	  
	  String id = getClientIdByName(clientId);
	  if(id == null) {
		  throw new NotFoundException("Client with id " + clientId + " not found!");
	  }
	  
	  // Get the id belonging to the client
	  Response res3 = this.getClient().
	      target(Accounts.baseUrl + "realms/{realm}/clients/{id}/service-account-user").
	      resolveTemplate("realm", realm).
	      resolveTemplate("id", id).
	      request().
	      header("Authorization", "Bearer " + this.getAuthToken()).
	      header("Accept", "application/json").
	      buildGet().
	      invoke();
	  
	  System.out.println("REQ OK");
	  
	  String clientSub = null;
	  if (res3.getStatus() == 200) {				
		  Accounts.log.info("Got the Service account id (sub of the client!)");
		  
		  String body = res3.readEntity(String.class);
		  Accounts.log.info("Reply: " + res3.getStatus());
		  Accounts.log.info("Body: " + body);
		  JSONObject reply = new JSONObject(body);
		  clientSub = reply.getString("id");
	  } else {
		  throw new NotFoundException("Cannot find the given client id " + clientId);
	  }

      JSONObject json = new JSONObject().
          put("client_id", clientId).
          put("sub", clientSub);
      
      if(getSecret) {
    	  String secret = getClientSecret(clientId);
    	  json.put("secret", secret);
      }
      
      return json;
  }

  //file:///home/boldt/Schreibtisch/KeyCloak/Keycloak%20Admin%20REST%20API.html#_delete_the_client
  
  public boolean deleteClient(String clientId) {
	  
	  System.out.println("Delete client with clientId " + clientId);
	  
	  String id = getClientIdByName(clientId);
	  if(id == null) {
		  throw new NotFoundException("Client with id " + clientId + " not found!");
	  }
	  
	  // Get the id belonging to the client
	  Response res3 = this.getClient().
	      target(Accounts.baseUrl + "realms/{realm}/clients/{id}").
	      resolveTemplate("realm", realm).
	      resolveTemplate("id", id).
	      request().
	      header("Authorization", "Bearer " + this.getAuthToken()).
	      buildDelete().
	      invoke();
	  
	  System.out.println("Status: " + res3.getStatus());
	  
	  if (res3.getStatus() == Status.NO_CONTENT.getStatusCode()) {
		  return true;
	  } else {
		  throw new InternalServerErrorException("Unknown status code: " + res3.getStatus());
	  }

  }

  
  public JSONObject registerClient(String clientId, String[] roles, boolean getSecret) {

	  JSONObject clientJson = new JSONObject().
	      put("clientId", clientId).
	      put("enabled", true).
	      put("serviceAccountsEnabled", true).
	      put("standardFlowEnabled", true).
	      put("clientAuthenticatorType", "confidential").
	      put("directAccessGrantsEnabled", false).
	      put("protocol", "openid-connect");

	  Response res = this.getClient().
	      target(Accounts.baseUrl + "realms/{realm}/clients").
	      resolveTemplate("realm", realm).
	      request().
	      header("Authorization", "Bearer " + this.getAuthToken()).
	      header("Content-Type", "application/json").
	      buildPost(Entity.json(clientJson.toString())).
	      invoke();

	  System.out.println("Status for client creation: " + res.getStatus());
	  
	  // New client created
	  if(res.getStatus() == Status.CREATED.getStatusCode()) {

		  Accounts.log.info("CLIENT CREATED");
		  
		  // Get the id belonging to the client
		  Response res3 = this.getClient().
		      target(Accounts.baseUrl + "realms/{realm}/clients/{id}/service-account-user").
		      resolveTemplate("realm", realm).
		      resolveTemplate("id", getClientIdByName(clientId)).
		      request().
		      header("Authorization", "Bearer " + this.getAuthToken()).
		      header("Accept", "application/json").
		      buildGet().
		      invoke();
		  
		  String clientSub = null;
		  if (res3.getStatus() == 200) {				
			  Accounts.log.info("Got the Service account id (sub of the client!)");
			  
			  String body = res3.readEntity(String.class);
			  Accounts.log.info("Reply: " + res3.getStatus());
			  Accounts.log.info("Body: " + body);
			  JSONObject reply = new JSONObject(body);
			  clientSub = reply.getString("id");
		  } else {
			  throw new InternalServerErrorException("Cannot find client id of just created client!");
		  }
		  
		  if(roles.length > 0) {
			  for (String role : roles) {
				  // Role does not exists!
				  if(!this.setUserRole(clientSub, role)) {
					  // Do the rollback and throw an exception
					  this.deleteClient(clientId);
					  throw new BadRequestException("Client canot be not created. The role " + role + " is unknown.");
				  } 
			  }
		  }

          JSONObject json = new JSONObject().
              put("client_id", clientId).
              put("sub", clientSub);

          // Ass secret, if allowed!
          if(getSecret) {
        	  try {
        		  String secret = getClientSecret(clientId);
        		  json.put("secret", secret);
        	  } catch (InternalServerErrorException e) {
				  this.deleteClient(clientId);
				  throw e;
        	  }
          }
          
          return json;

	  } else if(res.getStatus() == Status.CONFLICT.getStatusCode()){
		  throw new BadRequestException("ClientID already used");
	  } else {
		  System.out.println("STATUS: " + res.getStatus());
		  throw new InternalServerErrorException("Unkown Error");
	  }
  }
  
  private String getClientSecret(String clientId) throws InternalServerErrorException {

      String query = "select secret from CLIENT where client_id = '" + clientId + "';";
      Accounts.log.debug("Query:" + query);
	  
      Connection conn = null;
      Statement stmt = null;
      ResultSet rs = null;
      try {
        Accounts.log.debug("Load mysql driver");
        Class.forName("com.mysql.jdbc.Driver").newInstance();
        Accounts.log.debug("Connect to DB");
        conn = DriverManager.getConnection(mysqlconfig.getConnectionUrl(),
          mysqlconfig.getConnectionUser(),
          mysqlconfig.getConnectionPassword());
        stmt = conn.createStatement();
        Accounts.log.debug("Execute Query");
        rs = stmt.executeQuery(query);
        if (rs.next()) {
          Accounts.log.debug("FOUND!");
          return rs.getString("secret");
        }
      } catch (Exception e) {
        e.printStackTrace();
        Accounts.log.info("MySQL Error!");
        throw new InternalServerErrorException(e);
      } finally {
        try {
          if (rs != null) rs.close();
        } catch (SQLException e) {
          e.printStackTrace();
	        throw new InternalServerErrorException(e);
        }
        try {
          if (stmt != null) stmt.close();
        } catch (SQLException e) {
          e.printStackTrace();
	        throw new InternalServerErrorException(e);
        }
        try {
          if (conn != null) conn.close();
        } catch (SQLException e) {
          e.printStackTrace();
	        throw new InternalServerErrorException(e);
        }
      }	  
      throw new InternalServerErrorException("Unknown error");
  }
  
  public List<String> getSubsPerRole(String role) throws InternalServerErrorException {

	  String query = "SELECT user_id FROM KEYCLOAK_ROLE kr JOIN USER_ROLE_MAPPING rm ON kr.id = rm.role_id JOIN USER_ENTITY ue ON rm.user_id = ue.id WHERE kr.name = '" + role + "';";
      Accounts.log.debug("Query:" + query);
	  
      Connection conn = null;
      Statement stmt = null;
      ResultSet rs = null;
      try {
        Accounts.log.debug("Load mysql driver");
        Class.forName("com.mysql.jdbc.Driver").newInstance();
        Accounts.log.debug("Connect to DB");
        conn = DriverManager.getConnection(mysqlconfig.getConnectionUrl(),
          mysqlconfig.getConnectionUser(),
          mysqlconfig.getConnectionPassword());
        stmt = conn.createStatement();
        Accounts.log.debug("Execute Query");
        rs = stmt.executeQuery(query);
        List<String> result = new LinkedList<>();
        while (rs.next()) {
          //Accounts.log.debug("FOUND!");
          result.add(rs.getString("user_id"));
        }
        return result;
      } catch (Exception e) {
        e.printStackTrace();
        Accounts.log.info("MySQL Error!");
        throw new InternalServerErrorException(e);
      } finally {
        try {
          if (rs != null) rs.close();
        } catch (SQLException e) {
          e.printStackTrace();
	        throw new InternalServerErrorException(e);
        }
        try {
          if (stmt != null) stmt.close();
        } catch (SQLException e) {
          e.printStackTrace();
	        throw new InternalServerErrorException(e);
        }
        try {
          if (conn != null) conn.close();
        } catch (SQLException e) {
          e.printStackTrace();
	        throw new InternalServerErrorException(e);
        }
      }	  
  }  
  
  public boolean resetPassword(String userId, String password) {

	  System.out.println("Reset password for user with userId" + userId);

	  JSONObject json = new JSONObject().put("type", "password").
			  	put("value", password).
			  	put("temporary", false);

	  System.out.println(json.toString());

	  // Get the id belonging to the client
	  Response res = this.getClient().
	      target(Accounts.baseUrl + "realms/{realm}/users/{userId}/reset-password").
	      resolveTemplate("realm", realm).
	      resolveTemplate("userId", userId).
	      request().
	      header("Authorization", "Bearer " + this.getAuthToken()).
	      buildPut(Entity.json(json.toString())).
	      invoke();

	  System.out.println("Status: " + res.getStatus());

	  if (res.getStatus() == Status.NO_CONTENT.getStatusCode()) {
		  return true;
	  } else if (res.getStatus() == Status.BAD_REQUEST.getStatusCode()) {
		  String body = res.readEntity(String.class);
		  throw new InternalServerErrorException(body);
	  } else {
		  throw new InternalServerErrorException("Unknown status code: " + res.getStatus());
	  }
  }
}
