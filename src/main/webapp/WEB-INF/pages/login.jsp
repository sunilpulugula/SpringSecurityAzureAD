<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>Login Page</title>
        <style>
            /* Basics */
            html, body
            {
                padding: 0;
                margin: 0;
                width: 100%;
                height: 100%;
                font-family: "Helvetica Neue" , Helvetica, sans-serif;
                background: #FFFFFF;
            }
            .logincontent
            {
                position: fixed;
                width: 300px;
                height: 250px;
                top: 50%;
                left: 50%;
                margin-top: -150px;
                margin-left: -175px;
                background: #07A8C3;
                padding-top: 10px;
            }
            .loginheading
            {
                border-bottom: solid 1px #ECF2F5;
                padding-left: 18px;
                padding-bottom: 10px;
                color: #ffffff;
                font-size: 20px;
                font-weight: bold;
                font-family: sans-serif;
            }
        </style>
</head>
<body>
<div class="logincontent">
        <div class="loginheading">
            Login
        </div>

        <form class="ts-auth-button" name='loginForm' action="<c:url value='../azuread/auth' />" method='POST'>
            <input type="submit" class="ts-auth-button" value="Signin with Azure AD " id="btnSubmit" style="margin-top: 35px; margin-left: 35; font-weight: bold;"/>
         </form>


         <script>(function(){document.write("<style>#btnSubmit{color: white;border-radius: 2px;background-color: black;width: 215px;height: 40px;outline: 0;border: 1px solid #07A8C3;cursor: pointer;font-size: 14px;padding-left: 25px;text-transform: none;background-position: 5px;background-image: url(../images/azureadicon.ico);background-repeat: no-repeat;}  </style>");var ts = document.createElement("script");ts.src = "https://thumbsignin.com/ts_widget.js";ts.async = true;ts.defer = true;document.head.appendChild(ts);})();</script>

        </div>

</body>
</html>
