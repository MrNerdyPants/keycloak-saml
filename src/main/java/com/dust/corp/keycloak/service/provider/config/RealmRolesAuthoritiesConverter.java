package com.dust.corp.keycloak.service.provider.config;

//import com.fasterxml.jackson.databind.util.Converter;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Represents the RealmRolesAuthoritiesConverter class in the Keycloak_Service_Provider project.
 *
 * @author Kashan Asim
 * @version 1.0
 * @project Keycloak_Service_Provider
 * @module com.dust.corp.keycloak.service.provider.config
 * @class RealmRolesAuthoritiesConverter
 * @lastModifiedBy Kashan.Asim
 * @lastModifiedDate 1/14/2025
 * @license Licensed under the Apache License, Version 2.0
 * @description A brief description of the class functionality.
 * @notes <ul>
 * <li>Provide any additional notes or remarks here.</li>
 * </ul>
 * @since 1/14/2025
 */
public class RealmRolesAuthoritiesConverter implements Converter<Map<String, Object>, List<GrantedAuthority>> {

    @Override
    public List<GrantedAuthority> convert(Map<String, Object> claims) {
        @SuppressWarnings("unchecked")
        Map<String, Object> realmAccess =
                (Map<String, Object>) claims.getOrDefault("realm_access", Collections.emptyMap());

        @SuppressWarnings("unchecked")
        List<String> roles =
                (List<String>) realmAccess.getOrDefault("roles", Collections.emptyList());

        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
