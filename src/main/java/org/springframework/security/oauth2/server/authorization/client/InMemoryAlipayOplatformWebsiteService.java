package org.springframework.security.oauth2.server.authorization.client;

/*-
 * #%L
 * spring-boot-starter-alipay-oplatform
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.request.AlipaySystemOauthTokenRequest;
import com.alipay.api.request.AlipayUserInfoShareRequest;
import com.alipay.api.response.AlipaySystemOauthTokenResponse;
import com.alipay.api.response.AlipayUserInfoShareResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AlipayOplatformWebsiteAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.exception.AppidAlipayOplatformWebsiteException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectAlipayOplatformWebsiteException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriAlipayOplatformWebsiteException;
import org.springframework.security.oauth2.server.authorization.properties.AlipayOplatformWebsiteProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AlipayOplatformWebsiteEndpointUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AlipayOplatformWebsiteEndpointUtils.AUTH_ALIPAY_SYSTEM_OAUTH_TOKEN_URI;
import static org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AlipayOplatformWebsiteEndpointUtils.AUTH_ALIPAY_USER_INFO_SHARE_URI;

/**
 * 支付宝 网站应用 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class InMemoryAlipayOplatformWebsiteService implements AlipayOplatformWebsiteService {

	private final AlipayOplatformWebsiteProperties alipayOplatformWebsiteProperties;

	public InMemoryAlipayOplatformWebsiteService(AlipayOplatformWebsiteProperties alipayOplatformWebsiteProperties) {
		this.alipayOplatformWebsiteProperties = alipayOplatformWebsiteProperties;
	}

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 开放平台 网站应用 ID
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public String getRedirectUriByAppid(String appid) throws OAuth2AuthenticationException {
		AlipayOplatformWebsiteProperties.AlipayOplatformWebsite alipayOplatformWebsite = getAlipayOplatformWebsiteByAppid(
				appid);
		String redirectUriPrefix = alipayOplatformWebsite.getRedirectUriPrefix();

		if (StringUtils.hasText(redirectUriPrefix)) {
			return UriUtils.encode(redirectUriPrefix + "/" + appid, StandardCharsets.UTF_8);
		}
		else {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayOplatformWebsiteEndpointUtils.ERROR_CODE, "重定向地址前缀不能为空",
					null);
			throw new RedirectUriAlipayOplatformWebsiteException(error);
		}
	}

	/**
	 * 生成状态码
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @return 返回生成的授权码
	 */
	@Override
	public String stateGenerate(HttpServletRequest request, HttpServletResponse response, String appid) {
		return UUID.randomUUID().toString();
	}

	/**
	 * 储存绑定参数
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param state 状态码
	 * @param binding 绑定参数
	 */
	@Override
	public void storeBinding(HttpServletRequest request, HttpServletResponse response, String appid, String state,
			String binding) {

	}

	/**
	 * 储存操作用户
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param state 状态码
	 * @param binding 绑定参数
	 */
	@Override
	public void storeUsers(HttpServletRequest request, HttpServletResponse response, String appid, String state,
			String binding) {

	}

	/**
	 * 状态码验证（返回 {@link Boolean#FALSE} 时，将终止后面需要执行的代码）
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param code 授权码
	 * @param state 状态码
	 * @return 返回 状态码验证结果
	 */
	@Override
	public boolean stateValid(HttpServletRequest request, HttpServletResponse response, String appid, String code,
			String state) {
		return true;
	}

	/**
	 * 获取 绑定参数
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param code 授权码
	 * @param state 状态码
	 * @return 返回 绑定参数
	 */
	@Override
	public String getBinding(HttpServletRequest request, HttpServletResponse response, String appid, String code,
			String state) {
		return null;
	}

	/**
	 * 根据 appid 获取 支付宝 网站应用属性配置
	 * @param appid 公众号ID
	 * @return 返回 支付宝 网站应用属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AlipayOplatformWebsiteProperties.AlipayOplatformWebsite getAlipayOplatformWebsiteByAppid(String appid)
			throws OAuth2AuthenticationException {
		List<AlipayOplatformWebsiteProperties.AlipayOplatformWebsite> list = alipayOplatformWebsiteProperties.getList();
		if (list == null) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayOplatformWebsiteEndpointUtils.ERROR_CODE, "appid 未配置",
					null);
			throw new AppidAlipayOplatformWebsiteException(error);
		}

		for (AlipayOplatformWebsiteProperties.AlipayOplatformWebsite alipayOplatformWebsite : list) {
			if (appid.equals(alipayOplatformWebsite.getAppId())) {
				return alipayOplatformWebsite;
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2AlipayOplatformWebsiteEndpointUtils.ERROR_CODE, "未匹配到 appid", null);
		throw new AppidAlipayOplatformWebsiteException(error);
	}

	/**
	 * 获取 OAuth 2.1 授权 Token（如果不想执行此方法后面的内容，可返回 null）
	 * @param request 请求
	 * @param response 响应
	 * @param clientId 客户ID
	 * @param clientSecret 客户凭证
	 * @param tokenUrlPrefix 获取 Token URL 前缀
	 * @param tokenUrl Token URL
	 * @param uriVariables 参数
	 * @return 返回 OAuth 2.1 授权 Token
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@SuppressWarnings("AlibabaLowerCamelCaseVariableNaming")
	@Override
	public OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request,
			HttpServletResponse response, String clientId, String clientSecret, String tokenUrlPrefix, String tokenUrl,
			Map<String, String> uriVariables) throws OAuth2AuthenticationException {

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);

		MultiValueMap<String, String> multiValueMap = new LinkedMultiValueMap<>(8);
		multiValueMap.put(OAuth2ParameterNames.CLIENT_ID, Collections.singletonList(clientId));
		multiValueMap.put(OAuth2ParameterNames.CLIENT_SECRET, Collections.singletonList(clientSecret));

		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(multiValueMap, httpHeaders);
		RestTemplate restTemplate = new RestTemplate();
		List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
		messageConverters.add(5, new OAuth2AccessTokenResponseHttpMessageConverter());

		return restTemplate.postForObject(tokenUrlPrefix + tokenUrl, httpEntity, OAuth2AccessTokenResponse.class,
				uriVariables);
	}

	/**
	 * 根据 AppID、code、accessTokenUrl 获取Token
	 * @param appid AppID
	 * @param code 授权码
	 * @param state 状态码
	 * @param binding 是否绑定，需要使用者自己去拓展
	 * @param remoteAddress 用户IP
	 * @param sessionId SessionID
	 * @return 返回 支付宝授权结果
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AlipayOplatformWebsiteTokenResponse getAccessTokenResponse(String appid, String code, String state,
			String binding, String remoteAddress, String sessionId) throws OAuth2AuthenticationException {

		AlipayOplatformWebsiteProperties.AlipayOplatformWebsite alipayConfig = getAlipayOplatformWebsiteByAppid(appid);

		AlipayClient alipayClient;
		try {
			alipayClient = new DefaultAlipayClient(alipayConfig);
		}
		catch (AlipayApiException e) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayOplatformWebsiteEndpointUtils.ERROR_CODE, "创建支付宝网站应用配置异常",
					AUTH_ALIPAY_SYSTEM_OAUTH_TOKEN_URI);
			throw new OAuth2AuthenticationException(error);
		}

		AlipaySystemOauthTokenRequest systemOauthTokenRequest = new AlipaySystemOauthTokenRequest();
		systemOauthTokenRequest.setCode(code);
		systemOauthTokenRequest.setGrantType("authorization_code");

		AlipaySystemOauthTokenResponse systemOauthTokenResponse;
		try {
			systemOauthTokenResponse = alipayClient.execute(systemOauthTokenRequest);
		}
		catch (AlipayApiException e) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayOplatformWebsiteEndpointUtils.ERROR_CODE,
					"支付宝网站应用获取Token异常", AUTH_ALIPAY_SYSTEM_OAUTH_TOKEN_URI);
			throw new OAuth2AuthenticationException(error);
		}
		String systemOauthTokenResponseCode = systemOauthTokenResponse.getCode();

		String accessToken = systemOauthTokenResponse.getAccessToken();
		AlipayUserInfoShareRequest userInfoShareRequest = new AlipayUserInfoShareRequest();

		AlipayUserInfoShareResponse userInfoShareResponse;
		try {
			userInfoShareResponse = alipayClient.execute(userInfoShareRequest, accessToken);
		}
		catch (AlipayApiException e) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayOplatformWebsiteEndpointUtils.ERROR_CODE, "支付宝网站应用获取用户信息异常",
					AUTH_ALIPAY_USER_INFO_SHARE_URI);
			throw new OAuth2AuthenticationException(error);
		}
		String userInfoShareResponseCode = userInfoShareResponse.getCode();

		AlipayOplatformWebsiteTokenResponse alipayTokenResponse = new AlipayOplatformWebsiteTokenResponse();
		alipayTokenResponse.setSystemOauthTokenResponse(systemOauthTokenResponse);
		alipayTokenResponse.setUserInfoShareResponse(userInfoShareResponse);

		return alipayTokenResponse;
	}

	/**
	 * 构建 支付宝 网站应用 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID
	 * @param code 授权码
	 * @param userId
	 * @param openId 用户唯一标识
	 * @param credentials 证书
	 * @param unionid 多账户用户唯一标识
	 * @param accessToken 授权凭证
	 * @param refreshToken 刷新凭证
	 * @param expiresIn 过期时间
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String userId,
			String openId, Object credentials, String unionid, String accessToken, String refreshToken,
			String expiresIn) throws OAuth2AuthenticationException {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(
				alipayOplatformWebsiteProperties.getDefaultRole());
		authorities.add(authority);
		User user = new User(userId, accessToken, authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		AlipayOplatformWebsiteAuthenticationToken authenticationToken = new AlipayOplatformWebsiteAuthenticationToken(
				authorities, clientPrincipal, principal, user, additionalParameters, details, appid, code, userId,
				openId);

		authenticationToken.setCredentials(credentials);
		authenticationToken.setUnionid(unionid);

		return authenticationToken;
	}

	/**
	 * 授权成功重定向方法
	 * @param request 请求
	 * @param response 响应
	 * @param uriVariables 参数
	 * @param oauth2AccessTokenResponse OAuth2.1 授权 Token
	 * @param alipayOplatformWebsite 支付宝 网站应用 配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse,
			AlipayOplatformWebsiteProperties.AlipayOplatformWebsite alipayOplatformWebsite)
			throws OAuth2AuthenticationException {

		OAuth2AccessToken accessToken = oauth2AccessTokenResponse.getAccessToken();

		try {
			response.sendRedirect(alipayOplatformWebsite.getSuccessUrl() + "?"
					+ alipayOplatformWebsite.getParameterName() + "=" + accessToken.getTokenValue());
		}
		catch (IOException e) {
			OAuth2Error error = new OAuth2Error(OAuth2AlipayOplatformWebsiteEndpointUtils.ERROR_CODE, "支付宝 网站应用重定向异常",
					null);
			throw new RedirectAlipayOplatformWebsiteException(error, e);
		}

	}

}
