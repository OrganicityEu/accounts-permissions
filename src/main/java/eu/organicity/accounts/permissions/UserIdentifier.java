package eu.organicity.accounts.permissions;

import org.json.JSONObject;

public class UserIdentifier
{
  private String id;
  private String name;
  private String firstName;
  private String lastName;
  private String email;

  protected UserIdentifier(JSONObject json)
  {
	  System.out.println("JSON:" + json);
	  if(json.has("id")) {
		  this.id = json.getString("id");
	  }
	  if(json.has("username")) {
		  this.name = json.getString("username");
	  }
	  if(json.has("lastName")) {
		  this.lastName = json.getString("lastName");
	  }
	  if(json.has("firstName")) {
		  this.firstName = json.getString("firstName");
	  }
	  if(json.has("email")) {
		  this.email = json.getString("email");
	  }
  }

  public String getId()
  {
    return this.id;
  }

  public String getName() {
	return name;
  }

  public String getFirstName() {
	return firstName;
  }

  public String getLastName() {
	return lastName;
  }

  public String getEmail() {
	return email;
  }

  @Override
  public String toString() {
	return "UserIdentifier [id=" + id + ", name=" + name + ", firstName=" + firstName + ", lastName=" + lastName
			+ ", email=" + email + "]";
  }

}
