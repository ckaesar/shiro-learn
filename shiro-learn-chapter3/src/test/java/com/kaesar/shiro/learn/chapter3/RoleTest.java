package com.kaesar.shiro.learn.chapter3;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.apache.shiro.authz.UnauthorizedException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RoleTest extends BaseTest {
	
	private final static Logger LOGGER = LoggerFactory.getLogger(RoleTest.class);
	
	@Test
	public void testHasRole() {
		login("classpath:shiro-role.ini", "zhang", "123");
		//判断拥有角色：role1
		assertTrue(subject().hasRole("role1"));
		//判断拥有角色：role1 and role2
		assertTrue(subject().hasAllRoles(Arrays.asList("role1", "role2")));
		//判断拥有角色：role1 and role2 and !role3
		boolean[] result = subject().hasRoles(Arrays.asList("role1", "role2", "role3"));
		assertEquals(true, result[0]);
		assertEquals(true, result[1]);
		assertEquals(false, result[2]);
	}
	
	@Test(expected = UnauthorizedException.class)
	public void testCheckRole() {
		login("classpath:shiro-role.ini", "zhang", "123");
		//断言拥有角色：role1
		subject().checkRole("role1");
		//断言拥有角色：role1 and role3 失败抛出异常
		subject().checkRoles("role1", "role3");
	}
}
