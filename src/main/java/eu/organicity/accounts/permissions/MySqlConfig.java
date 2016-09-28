package eu.organicity.accounts.permissions;

public class MySqlConfig {

	
	public MySqlConfig(String connectionUrl, String connectionUser, String connectionPassword) {
		this.connectionUrl = connectionUrl;
		this.connectionUser = connectionUser;
		this.connectionPassword = connectionPassword;
	}
	
	private String connectionUrl;
	private String connectionUser;
	private String connectionPassword;
	
	public String getConnectionPassword() {
		return connectionPassword;
	}
	
	public String getConnectionUrl() {
		return connectionUrl;
	}
	
	public String getConnectionUser() {
		return connectionUser;
	}
	
}
