package com.kaesar.shiro.learn.chapter2;

import static org.junit.Assert.assertEquals;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticatorTest {
	
	private final static Logger LOGGER = LoggerFactory.getLogger(AuthenticatorTest.class);

	private void login(String configFile) {
	
		//1.获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
		Factory<org.apache.shiro.mgt.SecurityManager> factory = new IniSecurityManagerFactory(configFile);
		
		//2.得到SecurityManager实例，并绑定给SecurityUtils
		org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
		SecurityUtils.setSecurityManager(securityManager);
		
		//3.得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
		
		//4.登录，即身份验证
		subject.login(token);
	}
	
	@Test
	public void testAllSuccessfulStrategyWithSuccess() {
		login("classpath:shiro-authenticator-all-success.ini");
		Subject subject = SecurityUtils.getSubject();
		
		//得到一个集合，其包含了Realm验证成功的身份信息
		PrincipalCollection principalCollection = subject.getPrincipals();
		LOGGER.debug("principalCollection的个数：" + principalCollection.asList().size());
		assertEquals(2, principalCollection.asList().size());
	}
	
	@Test(expected = UnknownAccountException.class)
	public void testAllSuccessfulStrategyWithFail() {
		login("classpath:shiro-authenticator-all-fail.ini");
		Subject subject = SecurityUtils.getSubject();
	}
	
	@Test
	public void testAtLeastOneSuccessfulstrategyWithSuccess() {
		login("classpath:shiro-authenticator-atLeastOne-success.ini");
		Subject subject = SecurityUtils.getSubject();
		
		//得到一个身份集合，其包含了Realm验证成功的身份信息
		PrincipalCollection principalCollection = subject.getPrincipals();
		assertEquals(2, principalCollection.asList().size());
	}
	
	@Test
	public void testFirstOneSuccessfulStrategyWithSuccess() {
		login("classpath:shiro-authenticator-first-success.ini");
		Subject subject = SecurityUtils.getSubject();
		
		//得到一个身份集合，其包含了第一个Realm验证成功的身份信息
		PrincipalCollection principalCollection = subject.getPrincipals();
		assertEquals(1, principalCollection.asList().size());
	}
	
	@Test
	public void testAtLeastTwoStrategyWithSuccess() {
		login("classpath:shiro-authenticator-atLeastTwo-success.ini");
		Subject subject = SecurityUtils.getSubject();
		
		//得到一个身份集合，因为myRealm1和myRealm4返回的身份一样，所以输出时只返回一个
		PrincipalCollection principalCollection = subject.getPrincipals();
		assertEquals(1, principalCollection.asList().size());
	}
	
	@Test
	public void testOnlyOneStrategyWithSuccess() {
		login("classpath:shiro-authenticator-onlyone-success.ini");
		Subject subject = SecurityUtils.getSubject();
		
		//得到一个身份集合，因为myRealm1和myRealm4返回的身份一样，所以输出时只返回一个
		PrincipalCollection principalCollection = subject.getPrincipals();
		assertEquals(1, principalCollection.asList().size());
	}
	
	@After
    public void tearDown() throws Exception {
        ThreadContext.unbindSubject();//退出时请解除绑定Subject到线程 否则对下次测试造成影响
    }
}
