package com.iflytek.skillhub.auth.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;

/**
 * OAuth2 authorization request resolver that preserves a sanitized post-login
 * redirect target in the HTTP session.
 */
@Component
public class SkillHubOAuth2AuthorizationRequestResolver
        implements org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver delegate;
    private final OAuthLoginFlowService oauthLoginFlowService;

    public SkillHubOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                                      OAuthLoginFlowService oauthLoginFlowService) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                "/oauth2/authorization"
        );
        this.oauthLoginFlowService = oauthLoginFlowService;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest = addDingTalkOpenIdToAuthorizationUri(
                delegate.resolve(request)
        );
        oauthLoginFlowService.rememberReturnTo(request);
        return authorizationRequest;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest = addDingTalkOpenIdToAuthorizationUri(
                delegate.resolve(request, clientRegistrationId)
        );
        oauthLoginFlowService.rememberReturnTo(request);
        return authorizationRequest;
    }

    /**
     * 钉钉将 openid 作为普通 OAuth2 scope，但 Spring Security 会据此切换到 OIDC 并强制校验 id_token。
     * 因此只改写发往钉钉的授权 URL，保留内部 scopes 以继续走标准 OAuth2 授权码流程。
     */
    private OAuth2AuthorizationRequest addDingTalkOpenIdToAuthorizationUri(
            OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null
                || !"dingtalk".equals(
                authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID))) {
            return authorizationRequest;
        }

        LinkedHashSet<String> outboundScopes = new LinkedHashSet<>();
        outboundScopes.add("openid");
        outboundScopes.addAll(authorizationRequest.getScopes());
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .parameters(parameters ->
                        parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", outboundScopes)))
                .build();
    }
}
