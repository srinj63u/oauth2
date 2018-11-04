package com.srinj63u.oauth2.jwtsk.configuration;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {

	@Autowired
    private DataSource dataSource;
	
	@Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private Environment environment;

    @Value("${security.signing-key-file}")
    private String signingKeyFile;
    
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore())
                .tokenEnhancer(jwtTokenEnhancer())
                .authenticationManager(authenticationManager);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Bean
    public TokenStore tokenStore() throws IOException {
        return new JwtTokenStore(jwtTokenEnhancer());
    }
    
    private String fetchSigningKey() throws IOException {
        String filename = System.getProperty("user.home") + File.separator + signingKeyFile;
        Path newFilePath = Paths.get(filename);
        if (!Files.exists(newFilePath)) {
            // Generate the signing key if not exist.
            // (To be determined) If signing key will be stored in the file during the
            // initial deployment.
            RandomValueStringGenerator generator = new RandomValueStringGenerator();
            generator.setLength(30);
            String signingKey = generator.generate();
            Files.createFile(newFilePath);
            Files.write(newFilePath, signingKey.getBytes());
        }
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        return new String(keyBytes);
    }

    @Bean
    protected JwtAccessTokenConverter jwtTokenEnhancer() throws IOException {
    	String signingKey = fetchSigningKey();
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(signingKey);
        return converter;
    }

    /*
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("service-account-1")
                .secret("service-account-1-secret")
                .authorizedGrantTypes("client_credentials")
                .scopes("resource-server-read", "resource-server-write")
                .authorities("ROLE_RS_READ");;

    }*/
    
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    }
}