package com.ltpc.demo.jwt.filter;


import com.ltpc.demo.jwt.model.SSOUserInfo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * Created with IntelliJ IDEA.
 * User: liutong
 * Date: 2018/11/12
 * Time: 10:21 AM
 * Description:
 **/
public class JwtLoginFilter implements Filter {

    private static String TICKET_PARAM = "ticket";

    private static String USER_SESSION_NAME = "ssoUser";

    private static String SIGN_KEY;

    private static String SERVER_NAME;

    private static String SSO_SERVER_URL;

    private static String SSO_SERVER_LOGIN_URL;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String serverName = filterConfig.getInitParameter("serverName");
        String ssoServerUrl = filterConfig.getInitParameter("ssoServerUrl");
        String signKey = filterConfig.getInitParameter("signKey");
        String ssoServerLoginUrl = filterConfig.getInitParameter("ssoServerLoginUrl");
        SERVER_NAME = serverName;
        SIGN_KEY = signKey;
        SSO_SERVER_URL = ssoServerUrl;
        SSO_SERVER_LOGIN_URL = ssoServerLoginUrl;
    }


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession();
        String token = request.getParameter(TICKET_PARAM);
        if (token != null) {
            token = URLDecoder.decode(token, "UTF-8");
        }
        try {

            //解密token，拿到里面的对象claims
            SSOUserInfo clientUser = (SSOUserInfo) session.getAttribute(USER_SESSION_NAME);
            if(token != null && !token.trim().isEmpty()){
                clientUser = assembleUser(session, token);
            }

            if(clientUser!= null) {
                request.setAttribute(USER_SESSION_NAME,clientUser);
                request.setAttribute("loginName",clientUser.getLoginName());
            }else if(token == null || token.trim().isEmpty()){
                auth(httpRequest,httpResponse);
            }

        }catch (final SignatureException e) {
            e.printStackTrace();
            throw new ServletException("Invalid token.");
        } catch (Exception e){
            e.printStackTrace();
            throw new ServletException("Invalid token.");
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }

    /**
     * 封装用户信息
     *
     * @param session
     * @return
     */
    private SSOUserInfo assembleUser(HttpSession session, String token) {
        SSOUserInfo clientUser = new SSOUserInfo();

        // 根据code获取access_token
        final Claims claims = Jwts.parser().setSigningKey(SIGN_KEY).parseClaimsJws(token).getBody();
        clientUser.setAccountId(Long.parseLong((String)claims.get("accountId")));
        clientUser.setCustomerId(Long.parseLong((String)claims.get("customerId")));
        clientUser.setDepartmentId(Long.parseLong((String)claims.get("departmentId")));
        clientUser.setEmail((String)claims.get("email"));
        clientUser.setLoginName((String)claims.get("loginName"));
        clientUser.setSubCustomerame((String)claims.get("subCustomerame"));
        clientUser.setSubCustomerId(Long.parseLong((String)claims.get("subCustomerId")));
        clientUser.setTelephone((String)claims.get("telephone"));
        return clientUser;
    }

    /**
     * 跳转到认证系统
     *
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException
     */
    public void auth(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String uri = request.getRequestURI();
        String queryString =  request.getQueryString() != null ? "?"+request.getQueryString() : "";
        String redirectUri = URLEncoder.encode(SERVER_NAME + uri + queryString,"UTF-8");
        String ssoLogiUrl = SSO_SERVER_LOGIN_URL + "?service="+ redirectUri;
        System.out.println("redirect idp:"+ssoLogiUrl);
        response.sendRedirect(ssoLogiUrl);
        response.flushBuffer();
    }
}
