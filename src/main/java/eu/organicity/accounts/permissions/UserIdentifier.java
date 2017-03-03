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
	  this.id = json.getString("id");
	  this.name = json.getString("username");
	  this.lastName = json.getString("lastName");
	  this.firstName = json.getString("firstName");
	  this.email = json.getString("email");
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
