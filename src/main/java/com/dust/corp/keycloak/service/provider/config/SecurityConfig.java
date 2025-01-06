package com.dust.corp.keycloak.service.provider.config;

import com.dust.corp.keycloak.service.provider.exception.CustomSamlValidationException;
import org.opensaml.core.xml.schema.impl.XSStringImpl;
import org.opensaml.security.x509.X509Support;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

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

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(authorize -> authorize.anyRequest()
//                        .authenticated())
//                .saml2Login(withDefaults())
//                .saml2Metadata(withDefaults());
//        return http.build();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
        provider.setResponseValidator((responseToken) -> {
            Saml2ResponseValidatorResult result = OpenSaml4AuthenticationProvider
                    .createDefaultResponseValidator()
                    .convert(responseToken);
            if (result == null || result.hasErrors()) {
                String inResponseTo = responseToken.getResponse().getInResponseTo();
                throw new CustomSamlValidationException(inResponseTo);
            }
            LOG.info("SAML2 RESPONSE: {}", responseToken.getToken().getSaml2Response());
            return result;
        });

        provider.setResponseAuthenticationConverter(token -> {
            var auth = OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter().convert(token);
            LOG.info("AUTHORITIES: {}", auth.getAuthorities());

            var attrValues = token.getResponse().getAssertions().stream()
                    .flatMap(as -> as.getAttributeStatements().stream())
                    .flatMap(attrs -> attrs.getAttributes().stream())
                    .filter(attrs -> attrs.getName().equals("member"))
                    .findFirst().orElseThrow().getAttributeValues();

            if (!attrValues.isEmpty()) {
                var member = ((XSStringImpl) attrValues.get(0)).getValue();
                LOG.info("MEMBER: {}", member);
                List<GrantedAuthority> authoritiesList = List.of(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_" + member.toUpperCase().replaceFirst("/", ""))
                );

                LOG.info("NEW AUTHORITIES: {}", authoritiesList);
                return new Saml2Authentication((AuthenticatedPrincipal) auth.getPrincipal(), auth.getSaml2Response(), authoritiesList);
            } else return auth;
        });

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize.anyRequest()
                        .authenticated())
//                .saml2Login(withDefaults())
                .saml2Login(saml2 -> saml2
                        .authenticationManager(new ProviderManager(provider))
                )
                .saml2Metadata(withDefaults());
        return http.build();
    }

    @Bean
    Saml2AuthenticationRequestResolver authenticationRequestResolver(RelyingPartyRegistrationRepository registrations) {
        RelyingPartyRegistrationResolver registrationResolver =
                new DefaultRelyingPartyRegistrationResolver(registrations);
        OpenSaml4AuthenticationRequestResolver authenticationRequestResolver =
                new OpenSaml4AuthenticationRequestResolver(registrationResolver);
        authenticationRequestResolver.setAuthnRequestCustomizer((context) -> context
                .getAuthnRequest().setForceAuthn(true));
        return authenticationRequestResolver;
    }


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
                    .singleLogoutServiceLocation("http://localhost:8080/logout/saml2/slo")
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
