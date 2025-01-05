//package com.dust.corp.keycloak.service.provider.config;
//
//
//import jakarta.servlet.*;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//import java.util.stream.Collectors;
//
//@Component
//public class SamlLoggingFilter implements Filter {
//
//    private static final Logger logger = LoggerFactory.getLogger(SamlLoggingFilter.class);
//
//    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
//            throws IOException, ServletException {
//
//        HttpServletRequest httpRequest = (HttpServletRequest) request;
//        HttpServletResponse httpResponse = (HttpServletResponse) response;
//
//        // Check if the request is for SAML endpoints
//        if (httpRequest.getRequestURI().contains("/saml/SSO")) {
//            String samlRequest = httpRequest.getReader().lines().collect(Collectors.joining("\n"));
//            logger.info("SAML Request: {}", samlRequest);
//        }
//
//        chain.doFilter(request, response);
//
//        // Log SAML responses if applicable
//        if (httpResponse.getContentType() != null && httpResponse.getContentType().contains("xml")) {
//            logger.info("SAML Response: {}", response.toString());
//        }
//    }
//}
//
////        extends Saml2WebSsoAuthenticationFilter {
////
////    public SamlLoggingFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
////        super(relyingPartyRegistrationRepository);
////    }
////
////    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
////            throws ServletException, IOException {
////
////        if (request.getRequestURI().contains("/saml/SSO")) {
////            // Log SAML request details
////            System.out.println("SAML Request: " + request.getReader().lines().collect(Collectors.joining("\n")));
////        }
////
////        filterChain.doFilter(request, response);
////
////        if (response.getContentType() != null && response.getContentType().contains("xml")) {
////            // Log SAML response details
////            System.out.println("SAML Response: " + response.toString());
////        }
////    }
////}
////
