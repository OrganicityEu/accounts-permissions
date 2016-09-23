package eu.organicity.accounts.permissions;

public final class Role
{
  public final String Name;

  public final String Experiment;

  public Role(String name)
  {
    this.Name = name;
    this.Experiment = null;
  }

  public Role(String name, String experiment)
  {
    this.Name = name;
    this.Experiment = experiment;
  }
}
