package eu.organicity.accounts.permissions;

import java.util.List;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class AccountsTest {

	public static Accounts a;
	private String userId = "0dfc01f7-a234-4cbc-8e70-7ae361127dd4";
	private String role = "demo:demo-role1";
	private String clientId = "demo";
	
	@BeforeClass
	public static void setUpClass() {
		AccountsTest.a = Accounts.withBasicAuth(Config.basicAuth);
	}	
	
	@Test
	public void testGestToken() {
		String token = AccountsTest.a.getAuthToken();
		Assert.assertNotEquals(null, token);
	}

	@Test
	public void testRemoveRole() {
		Boolean status = a.removeUserRole(userId, role);
		Assert.assertEquals(true, status);
		
		List<String> roles = a.getUserRoles(userId, clientId);
		Assert.assertEquals(false, roles.contains(role));
	}	

	@Test
	public void testSetRole() {
		Boolean status = a.setUserRole(userId, role);
		Assert.assertEquals(true, status);
		
		List<String> roles = a.getUserRoles(userId, clientId);
		Assert.assertEquals(true, roles.contains(role));
	}	
	
	@Test
	public void testRemoveSetRemoveRole() {
		Boolean status = a.setUserRole(userId, role);
		Assert.assertEquals(true, status);
		
		List<String> roles = a.getUserRoles(userId, clientId);
		Assert.assertEquals(true, roles.contains(role));
		
		Boolean status3 = a.removeUserRole(userId, role);
		Assert.assertEquals(true, status3);
		
		List<String> roles3 = a.getUserRoles(userId, clientId);
		Assert.assertEquals(false, roles3.contains(role));		
	}		
	
	
}
