package com.ltpc.demo.jwt.filter;


import com.ltpc.demo.jwt.model.SSOUserInfo;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.AesKey;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Map;

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

    private static Key SIGN_KEY;

    private static Key DECRYPTION_KEY;

    private static String SERVER_NAME;

    private static String SSO_SERVER_URL;

    private static String SSO_SERVER_LOGIN_URL;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String serverName = filterConfig.getInitParameter("serverName");
        String ssoServerUrl = filterConfig.getInitParameter("ssoServerUrl");
        String ssoServerLoginUrl = filterConfig.getInitParameter("ssoServerLoginUrl");
        String signKey = filterConfig.getInitParameter("signKey");
        String decryptionKey = filterConfig.getInitParameter("decryptionKey");

        SERVER_NAME = serverName;
        SSO_SERVER_URL = ssoServerUrl;
        SSO_SERVER_LOGIN_URL = ssoServerLoginUrl;
        SIGN_KEY = new AesKey(signKey.getBytes(StandardCharsets.UTF_8));
        DECRYPTION_KEY = new AesKey(decryptionKey.getBytes(StandardCharsets.UTF_8));
    }


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession();
        String token = request.getParameter(TICKET_PARAM);
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
        System.out.println("=========================\n\r" + token);
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                // the JWT must have an expiration time
                .setRequireExpirationTime()
                // but the  expiration time can't be too crazy
                .setMaxFutureValidityInMinutes(4800)
                // allow some leeway in validating time based claims to account for clock skew
                .setAllowedClockSkewInSeconds(30)
                // the JWT must have a subject claim
                .setRequireSubject()
                // whom the JWT needs to have been issued by
                .setExpectedIssuer("http://localhost:8080/uac")
                // to whom the JWT is intended for
                .setExpectedAudience("http://localhost:8085/")
                // verify the signature with the public key
                .setVerificationKey(SIGN_KEY)
//                .setDecryptionKey(DECRYPTION_KEY)
                .build();
        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            System.out.println("JWT validation succeeded! " + jwtClaims);
            Map<String, Object> claims = jwtClaims.getClaimsMap();
            clientUser.setAccountId(Long.parseLong((String) claims.get("accountId")));
            clientUser.setCustomerId(Long.parseLong((String) claims.get("customerId")));
            String departmentId = (String)claims.get("departmentId");
            if(departmentId != null && departmentId.trim().length()>0 ) {
                clientUser.setDepartmentId(Long.parseLong((String) claims.get("departmentId")));
            }
            clientUser.setEmail((String) claims.get("email"));
            clientUser.setLoginName((String) claims.get("loginName"));
            clientUser.setSubCustomerame((String) claims.get("subCustomerame"));
            clientUser.setSubCustomerId(Long.parseLong((String) claims.get("subCustomerId")));
            clientUser.setTelephone((String) claims.get("telephone"));
        } catch (InvalidJwtException e) {
            e.printStackTrace();
        }
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
