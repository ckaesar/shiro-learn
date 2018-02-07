package com.kaesar.shiro.learn.chapter2.authenticator.strategy;

import java.util.Collection;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.pam.AbstractAuthenticationStrategy;
import org.apache.shiro.realm.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OnlyOneAuthenticatorStrategy extends AbstractAuthenticationStrategy {
	
	private final static Logger LOGGER = LoggerFactory.getLogger(OnlyOneAuthenticatorStrategy.class);

	@Override
	public AuthenticationInfo beforeAllAttempts(Collection<? extends Realm> realms, AuthenticationToken token) throws AuthenticationException {
        return new SimpleAuthenticationInfo(); //返回一个权限的认证信息
    }
	
	@Override
	public AuthenticationInfo beforeAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        return aggregate; //返回之前合并的
    }
	
	@Override
	public AuthenticationInfo afterAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo singleRealmInfo, AuthenticationInfo aggregateInfo, Throwable t) throws AuthenticationException {
        AuthenticationInfo info;
        if (singleRealmInfo == null) {
            info = aggregateInfo;
        } else {
            if (aggregateInfo == null) {
                info = singleRealmInfo;
            } else {
                info = merge(singleRealmInfo, aggregateInfo);
                if(info.getPrincipals().getRealmNames().size() > 1) {
                	LOGGER.debug("", info.getPrincipals().getRealmNames());
                	throw new AuthenticationException("Authentication token of type [" + token.getClass() + "]" + 
        					" could not be authenticated by any configured realms. Please ensure that at least two realm can " + 
        					"authenticate these tokens.");
                }
            }
        }

        return info;
    }
	
	@Override
	public AuthenticationInfo afterAllAttempts(AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        return aggregate;
    }
}
