package eu.organicity.accounts.permissions;

public class UserIdentifier
{
  private String name;
  private String id;

  protected UserIdentifier(String id, String name)
  {
    this.id = id;
    this.name = name;
  }

  public String getName()
  {
    return this.name;
  }

  public String getId()
  {
    return this.id;
  }
}
