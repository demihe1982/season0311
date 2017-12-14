package cn.dyan.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * init role match menu url
 */
public class MyFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private Map<RequestMatcher, Collection<ConfigAttribute>> requestMap;

    private final FilterInvocationSecurityMetadataSource metadataSource;

    public MyFilterInvocationSecurityMetadataSource(FilterInvocationSecurityMetadataSource metadataSource) {
        this.metadataSource = metadataSource;
        requestMap = new HashMap<RequestMatcher, Collection<ConfigAttribute>>();
        List<ConfigAttribute> configAttributes = new ArrayList<ConfigAttribute>();
        configAttributes.add(new SecurityConfig("ROLE_ADMIN"));
        requestMap.put(new AntPathRequestMatcher("/admin/**"), configAttributes);
        List<ConfigAttribute> configAttributes1 = new ArrayList<ConfigAttribute>();
        configAttributes1.add(new SecurityConfig("ROLE_USER"));
        requestMap.put(new AntPathRequestMatcher("/user/**"), configAttributes1);
    }

    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<ConfigAttribute>();

        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    public Collection<ConfigAttribute> getAttributes(Object object) {
        final HttpServletRequest request = ((FilterInvocation) object).getRequest();
        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            if (entry.getKey().matches(request)) {
                return entry.getValue();
            }
        }
        return metadataSource.getAttributes(object);
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
