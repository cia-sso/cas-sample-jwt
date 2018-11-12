<%@page contentType="text/html" %>
<%@page pageEncoding="UTF-8" %>
<%@ page import="java.util.List" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="com.ltpc.demo.jwt.model.SSOUserInfo" %>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">

<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>CAS Example jwt App</title>
</head>
<body>

<h1>CAS Example JWT App</h1>
<p>A sample web application that exercises the CAS protocol features via the JWT.</p>
<hr>

<p><b>Authenticated User Id:</b> <a href="logout.jsp" title="Click here to log out"><%= request.getAttribute("loginName") %>
</a></p>

<%
    if (request.getAttribute("ssoUser") != null) {
        SSOUserInfo clientUser = (SSOUserInfo) request.getAttribute("ssoUser");
        Field[] fields = clientUser.getClass().getDeclaredFields();
        if (clientUser != null) {
            out.println("<b>Attributes:</b>");

            if (fields.length > 0) {
                out.println("<hr><table border='3pt' width='100%'>");
                out.println("<th colspan='2'>Attributes</th>");
                out.println("<tr><td><b>Key</b></td><td><b>Value</b></td></tr>");

                for (Field field: fields) {
                    out.println("<tr><td>");
                    String attributeName = (String) field.getName();
                    out.println(attributeName);
                    out.println("</td><td>");
                    String firstLetter = attributeName.substring(0, 1).toUpperCase();
                    String getter = "get" + firstLetter + attributeName.substring(1);
                    Method method = clientUser.getClass().getMethod(getter, new Class[] {});
                    final Object attributeValue = method.invoke(clientUser, new Object[] {});

                    if (attributeValue instanceof List) {
                        final List values = (List) attributeValue;
                        out.println("<strong>Multi-valued attribute: " + values.size() + "</strong>");
                        out.println("<ul>");
                        for (Object value : values) {
                            out.println("<li>" + value + "</li>");
                        }
                        out.println("</ul>");
                    } else {
                        out.println(attributeValue);
                    }
                    out.println("</td></tr>");
                }
                out.println("</table>");
            } else {
                out.print("No attributes are supplied by the CAS server.</p>");
            }
        } else {
            out.println("<pre>The attribute map is empty. Review your CAS filter configurations.</pre>");
        }
    } else {
        out.println("<pre>The user principal is empty from the request object. Review the wrapper filter configuration.</pre>");
    }
%>

</body>
</html>
