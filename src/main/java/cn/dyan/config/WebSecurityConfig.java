package cn.dyan.config;

import cn.dyan.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

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

    @Bean
    public UserDetailsService userDetailsService(){
        CustomUserDetailService manager = new CustomUserDetailService();
        manager.setDataSource(dataSource);
        manager.setEnableGroups(true);
        return manager;
    }


}
