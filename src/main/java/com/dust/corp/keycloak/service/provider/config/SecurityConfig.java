package com.dust.corp.keycloak.service.provider.config;

//import com.fasterxml.jackson.databind.util.Converter;
import org.opensaml.security.x509.X509Support;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${saml2.ap.metadata.location}")
    private String metadataLocation;

    @Value("${saml2.rp.signing.cert-location}")
    private String rpSigningCertLocation;

    @Value("${saml2.rp.signing.key-location}")
    private String rpSigningKeyLocation;

    @Value("${saml2.ap.signing-cert}")
    private String apCertificate;

//    interface AuthoritiesConverter extends Converter<Map<String, Object>, Collection<GrantedAuthority>> {
//    }
//
//    @Bean
//    AuthoritiesConverter realmRolesAuthoritiesConverter() {
//        return claims -> {
//            if (claims instanceof Map<?, ?>) {
//                @SuppressWarnings("unchecked")
//                Map<String, Object> claimsMap = (Map<String, Object>) claims;
//
//                @SuppressWarnings("unchecked")
//                Map<String, Object> realmAccess =
//                        (Map<String, Object>) claimsMap.getOrDefault("realm_access", Collections.emptyMap());
//
//                @SuppressWarnings("unchecked")
//                List<String> roles =
//                        (List<String>) realmAccess.getOrDefault("roles", Collections.emptyList());
//
//                return roles.stream()
//                        .map(SimpleGrantedAuthority::new)
//                        .collect(Collectors.toList());
//            } else {
//                // Handle cases where claims is not a Map
//                // (e.g., log a warning or return an empty list)
//                log.warn("Claims object is not a Map: {}", claims);
//                return Collections.emptyList();
//            }
//        };
//    }

//    @Bean
//    public Function<Map<String, Object>, Collection<GrantedAuthority>> realmRolesAuthoritiesConverter() {
//        return claims -> {
//            @SuppressWarnings("unchecked")
//            Map<String, Object> realmAccess =
//                    (Map<String, Object>) claims.getOrDefault("realm_access", Collections.emptyMap());
//
//            @SuppressWarnings("unchecked")
//            List<String> roles =
//                    (List<String>) realmAccess.getOrDefault("roles", Collections.emptyList());
//
//            return roles.stream()
//                    .map(SimpleGrantedAuthority::new)
//                    .collect(Collectors.toList());
//        };
//    }


//    @Bean
//    AuthoritiesConverter realmRolesAuthoritiesConverter() {
//
//        return claims -> {
//
//            @SuppressWarnings("unchecked")
//            final var realmAccess = Optional.ofNullable((Map<String, Object>) claims.get("realm_access"));
//            final var roles =
//                    realmAccess.flatMap(map -> Optional.ofNullable((List<String>) map.get("roles")));
//            return roles.map(List::stream).orElse(Stream.empty()).map(SimpleGrantedAuthority::new)
//                    .map(GrantedAuthority.class::cast).toList();
//        };
//    }

//    @Bean
//    GrantedAuthoritiesMapper authenticationConverter(
//            Converter<Map<String, Object>, Collection<GrantedAuthority>> realmRolesAuthoritiesConverter) {
//        return (authorities) -> authorities.stream()
//                .filter(authority -> authority instanceof OidcUserAuthority)
//                .map(OidcUserAuthority.class::cast).map(OidcUserAuthority::getIdToken)
//                .map(OidcIdToken::getClaims).map(realmRolesAuthoritiesConverter::convert)
//                .flatMap(roles -> roles.stream()).collect(Collectors.toSet());
//    }

    @Bean
    public Converter<Map<String, Object>, List<GrantedAuthority>> realmRolesAuthoritiesConverter() {
        return new RealmRolesAuthoritiesConverter();
    }


    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http,
                                                  ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        http.oauth2Login(Customizer.withDefaults());
        http.logout((logout) -> {
            final var logoutSuccessHandler =
                    new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
            logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");
            logout.logoutSuccessHandler(logoutSuccessHandler);
        });

        http.authorizeHttpRequests(requests -> {
            requests.requestMatchers("/", "/favicon.ico").permitAll();
            requests.requestMatchers("/nice").hasAuthority("NICE");
            requests.anyRequest().denyAll();
        });

        return http.build();
    }


//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/ping").permitAll()
//                        .requestMatchers("/").permitAll()
//                        .requestMatchers("**").authenticated()
//                )
//                .logout(logout -> logout
//                        .logoutUrl("/")
//                )
//                // Konfiguration des SAML SSO-Logins
//                .saml2Login(withDefaults())
//                // und des SAML SSO-Logouts
//                .saml2Logout(withDefaults())
//        ;
//        return http.build();
//    }

    /**
     * Erzeugen der RelyingParty (das sind wir!) registration repositories. Für jeden SAML IDP gibt es einen
     * Eintrag. Jede Registration hat eine "registrationId", aus der sich die URLs für die Endpoints
     * ergeben. In diesem Beispiel ist die registrationID "samp-app" daraus ergeben sich die URLs
     * für Login und Logout wie folgt:
     * Login: /login/saml2/sso/saml-app
     * Logout: /logout/saml2/slo
     *
     * @return
     * @throws Exception
     */
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
        Resource signingCertResource = new ClassPathResource(this.rpSigningCertLocation);
        Resource signingKeyResource = new ClassPathResource(this.rpSigningKeyLocation);
        try (
                InputStream is = signingKeyResource.getInputStream();
                InputStream certIS = signingCertResource.getInputStream();
        ) {
            X509Certificate rpCertificate = X509Support.decodeCertificate(certIS.readAllBytes());
            RSAPrivateKey rpKey = RsaKeyConverters.pkcs8().convert(is);
            final Saml2X509Credential rpSigningCredentials = Saml2X509Credential.signing(rpKey, rpCertificate);

            X509Certificate apCert = X509Support.decodeCertificate(apCertificate);
            Saml2X509Credential apCredential = Saml2X509Credential.verification(apCert);

            RelyingPartyRegistration registration = RelyingPartyRegistrations
                    .fromMetadataLocation(metadataLocation)
                    .registrationId("saml-client-springboot")
                    .singleLogoutServiceLocation("{baseUrl}/logout/saml2/slo")
                    .signingX509Credentials(c -> c.add(rpSigningCredentials))
                    .assertingPartyDetails(party -> party
                            .wantAuthnRequestsSigned(true)
                            .verificationX509Credentials(c -> c.add(apCredential))
                    )
                    .build();
            return new InMemoryRelyingPartyRegistrationRepository(registration);
        }
    }

}
