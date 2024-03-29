package org.springframework.security.oauth2.server.authorization.http;

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

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2AlipayOplatformWebsiteParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.AlipayOplatformWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.AlipayOplatformWebsiteProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 支付宝 网站应用 跳转到支付宝授权页面
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class AlipayOplatformWebsiteAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/alipay-oplatform/website/authorize";

	public static final String AUTHORIZE_URL = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id=%s&redirect_uri=%s&scope=%s&state=%s";

	public static final String AUTH_USER = "auth_user";

	private AlipayOplatformWebsiteProperties alipayOplatformWebsiteProperties;

	private AlipayOplatformWebsiteService alipayOplatformWebsiteService;

	/**
	 * 支付宝 网站应用 授权前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Autowired
	public void setAlipayOplatformWebsiteProperties(AlipayOplatformWebsiteProperties alipayOplatformWebsiteProperties) {
		this.alipayOplatformWebsiteProperties = alipayOplatformWebsiteProperties;
	}

	@Autowired
	public void setAlipayOplatformWebsiteService(AlipayOplatformWebsiteService alipayOplatformWebsiteService) {
		this.alipayOplatformWebsiteService = alipayOplatformWebsiteService;
	}

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");

			String redirectUri = alipayOplatformWebsiteService.getRedirectUriByAppid(appid);

			String binding = request.getParameter(OAuth2AlipayOplatformWebsiteParameterNames.BINDING);
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			if (!AUTH_USER.equals(scope)) {
				scope = AUTH_USER;
			}

			String state = alipayOplatformWebsiteService.stateGenerate(request, response, appid);
			alipayOplatformWebsiteService.storeBinding(request, response, appid, state, binding);
			alipayOplatformWebsiteService.storeUsers(request, response, appid, state, binding);

			String url = String.format(AUTHORIZE_URL, appid, redirectUri, scope, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
