
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
import java.io.IOException;
import java.util.Scanner;


public class Accounts
{
  private static Logger log = LoggerFactory.getLogger(Accounts.class);

  private static String baseUrl = "https://accounts.organicity.eu/admin/";

  public String getUserRoles(String userId)
  {
    this.log.info("Requesting user roles for " + userId);

    Client c = ClientBuilder.newClient();

    WebTarget t = c.target(this.baseUrl + "realms/organicity/users/" + userId +
                           "/role-mappings/realm");

    Builder b = t.request();

    Invocation i = b.buildGet();

    Response r = i.invoke();


    MultivaluedMap<String, Object> headers = r.getHeaders();

    this.log.info("Reply Status Code: " + r.getStatus());


    for (Map.Entry<String, List<Object>> entry : headers.entrySet()) {
      this.log.info("Header: " + entry.getKey() + ":");

      for (Object value: entry.getValue()) {
        String valueString = value.toString();
        this.log.info(valueString);
      }
    }


    String body = r.readEntity(String.class);

    this.log.info("Body: " + body);

    return body;
  }


  public String login()
  {
    // Connects with the accounts-permissions service account.
    this.log.info("Logging in with accounts-permissions.");

    Client c = ClientBuilder.newClient();
    // c.register(
    //   new ClientRequestFilter() {
    //     private Logger log = LoggerFactory.getLogger(ClientRequestFilter.class);

    //     public void filter(ClientRequestContext requestContext)
    //       throws IOException {
    //       this.log.info(requestContext.toString());
    //     }
    //   }
    // );

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

          this.log.trace("Executing Request:");
          this.log.trace(req.getMethod() + " " +
                         req.getUri().toString());
          Map<String, List<Object>> headers = req.getHeaders();
          for (Map.Entry<String, List<Object>> header : headers.entrySet()) {
            this.log.trace(header.getKey() + ": " +
                           this.join(", ", header.getValue()));
          }

          Object reqEntity = req.getEntity();
          if (reqEntity != null) {
            this.log.trace("");
            this.log.trace(reqEntity.toString());
          }

          this.log.trace("");

          this.log.trace("Response:");
          this.log.trace("HTTP " + res.getStatus());
          Map<String, List<String>> resHeaders = res.getHeaders();
          for (Map.Entry<String, List<String>> header : resHeaders.entrySet()) {
            this.log.trace(header.getKey() + ": " +
                           this.joinStrings(", ", header.getValue()));
          }

          if (res.hasEntity()) {
            Scanner s = new Scanner(res.getEntityStream()).useDelimiter("\\A");
            String resEntity = s.hasNext() ? s.next() : "";

            this.log.trace("");
            this.log.trace(resEntity);
          }

          this.log.trace("");
        }
      }
    );

    String url = "https://accounts.organicity.eu/realms/organicity/" +
      "protocol/openid-connect/token";
    Response r = c.target(url).
      request().
      buildPost(Entity.form(new Form("grant_type", "client_credentials"))).
      invoke();

    String body = r.readEntity(String.class);

    this.log.info("Reply: " + r.getStatus());
    this.log.info("Body: " + body);

    return body;
  }
}
