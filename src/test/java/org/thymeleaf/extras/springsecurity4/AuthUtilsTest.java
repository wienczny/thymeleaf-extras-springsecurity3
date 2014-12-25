package org.thymeleaf.extras.springsecurity4;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AbstractAclVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.thymeleaf.exceptions.TemplateProcessingException;
import org.thymeleaf.extras.springsecurity4.auth.AuthUtils;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests for {@link org.thymeleaf.extras.springsecurity4.auth.AuthUtils}
 */
public class AuthUtilsTest {

    @Test
    public void testGetAuthenticationObjectWithoutContext() {
        final Authentication authentication = AuthUtils.getAuthenticationObject();
        assertThat(authentication).isNull();
    }

    @Test
    public void testGetAuthenticationObjectWithoutAuthentication() {
        // Initialize empty context
        final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(null);
        SecurityContextHolder.setContext(securityContext);

        final Authentication authentication = AuthUtils.getAuthenticationObject();

        assertThat(authentication).isNull();
    }

    @Test
    public void testGetAuthenticationObject() {
        final List<GrantedAuthority> authorities = new LinkedList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE"));

        final UserDetails userDetails = new User("username", "password", authorities);

        final AnonymousAuthenticationToken authenticationToken =
                new AnonymousAuthenticationToken("key", userDetails, authorities);

        // Initialize empty context
        final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authenticationToken);
        SecurityContextHolder.setContext(securityContext);

        final Authentication authentication = AuthUtils.getAuthenticationObject();

        assertThat(authentication).isEqualTo(authenticationToken);
    }

    @Test
    public void testGetAuthenticationPropertyWithoutAutentication() {
        final Object value = AuthUtils.getAuthenticationProperty(null, "principal");

        assertThat(value).isNull();
    }

    @Test(expected = TemplateProcessingException.class)
    public void testGetAuthenticationPropertyNonexistingProperty() {
        final List<GrantedAuthority> authorities = new LinkedList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE"));

        final UserDetails userDetails = new User("username", "password", authorities);

        final AnonymousAuthenticationToken authenticationToken =
                new AnonymousAuthenticationToken("key", userDetails, authorities);

        final Object value = AuthUtils.getAuthenticationProperty(authenticationToken, "NOTEXISTING");
    }

    @Test
    public void testGetAuthenticationProperty() {
        final List<GrantedAuthority> authorities = new LinkedList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE"));

        final UserDetails userDetails = new User("username", "password", authorities);

        final AnonymousAuthenticationToken authenticationToken =
                new AnonymousAuthenticationToken("key", userDetails, authorities);

        final Object value = AuthUtils.getAuthenticationProperty(authenticationToken, "principal");

        assertThat(value).isEqualTo(userDetails);
    }


    @Test
    public void testGetContext() {
        final DefaultListableBeanFactory dlbf = new DefaultListableBeanFactory();
        final GenericWebApplicationContext gwac = new GenericWebApplicationContext(dlbf);
        final MockServletContext mockServletContext = new MockServletContext();
        mockServletContext.setAttribute(
                GenericWebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, gwac);
        gwac.setServletContext(mockServletContext);
        gwac.refresh();

        ApplicationContext applicationContext = AuthUtils.getContext(mockServletContext);

        assertThat(applicationContext).isNotNull();
    }

    @Test
    public void testAuthorizeUsingUrlCheck() {
        final List<AccessDecisionVoter<? extends Object>> decisionVoters =
                new LinkedList<AccessDecisionVoter<? extends Object>>();

        decisionVoters.add(new AbstractAclVoter() {
            public boolean supports(final ConfigAttribute attribute) {
                return true;
            }

            public int vote(final Authentication authentication, final MethodInvocation object,
                            final Collection<ConfigAttribute> attributes) {
                return ACCESS_GRANTED;
            }
        });

        final AffirmativeBased affirmativeBased = new AffirmativeBased(decisionVoters);

        final FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource =
                new DefaultFilterInvocationSecurityMetadataSource(
                        new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>());

        final FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased);
        filterSecurityInterceptor.setSecurityMetadataSource(filterInvocationSecurityMetadataSource);

        final DefaultWebInvocationPrivilegeEvaluator webInvocationPrivilegeEvaluator =
                new DefaultWebInvocationPrivilegeEvaluator(filterSecurityInterceptor);

        final DefaultListableBeanFactory dlbf = new DefaultListableBeanFactory();
        dlbf.registerSingleton(webInvocationPrivilegeEvaluator.getClass().getCanonicalName(),
                webInvocationPrivilegeEvaluator);

        final GenericWebApplicationContext gwac = new GenericWebApplicationContext(dlbf);

        final MockServletContext mockServletContext = new MockServletContext();
        mockServletContext.setAttribute(
                GenericWebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, gwac);
        gwac.setServletContext(mockServletContext);
        gwac.refresh();

        final List<GrantedAuthority> authorities = new LinkedList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE"));

        final UserDetails userDetails = new User("username", "password", authorities);

        final AnonymousAuthenticationToken authenticationToken =
                new AnonymousAuthenticationToken("key", userDetails, authorities);

        final HttpServletRequest mockServletRequest = new MockHttpServletRequest(mockServletContext);

        boolean authorized = AuthUtils.authorizeUsingUrlCheck("url", "POST", authenticationToken,
                mockServletRequest, mockServletContext);

        assertThat(authorized).isTrue();
    }

}
