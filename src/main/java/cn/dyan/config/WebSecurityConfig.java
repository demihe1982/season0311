package cn.dyan.config;

import cn.dyan.security.MyAccessDecisionManager;
import cn.dyan.security.MyFilterInvocationSecurityMetadataSource;
import cn.dyan.security.MyFilterSecurityInterceptor;
import cn.dyan.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import javax.sql.DataSource;

/**
 *
 * 三种是细分角色和权限，并将用户、角色、权限和资源均采用数据库存储，
 * 并且自定义过滤器，代替原有的FilterSecurityInterceptor过滤器
 * 并分别实现AccessDecisionManager、InvocationSecurityMetadataSourceService和UserDetailsService，
 * 并在配置中进行相应配置。
 *
 *
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private MyAccessDecisionManager accessDecisionManager;

    @Autowired
    private MyFilterInvocationSecurityMetadataSource securityMetadataSource;

    @Bean
    public UserDetailsService userDetailsService(){
        CustomUserDetailService manager = new CustomUserDetailService();
        manager.setDataSource(dataSource);
        manager.setEnableGroups(true);
        return manager;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .addFilterBefore(getFilterSecurityInterceptor(),FilterSecurityInterceptor.class)
                .httpBasic();

    }

    private MyFilterSecurityInterceptor getFilterSecurityInterceptor(){
        MyFilterSecurityInterceptor filterSecurityInterceptor = new MyFilterSecurityInterceptor();
        filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager);
        filterSecurityInterceptor.setSecurityMetadataSource(securityMetadataSource);
        return filterSecurityInterceptor;
    }




}
