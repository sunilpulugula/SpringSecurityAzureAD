package com.geeksoverflow.security.azuread.controller;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.geeksoverflow.security.azuread.helper.AuthHelper;
import com.geeksoverflow.security.azuread.helper.HttpClientHelper;
import com.geeksoverflow.security.azuread.helper.JSONHelper;
import com.geeksoverflow.security.azuread.model.AzureADClientProps;
import com.geeksoverflow.security.azuread.model.User;
import com.microsoft.aad.adal4j.AuthenticationResult;


/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 22/3/16
 */
@RestController
public class PagesController {

    @Autowired
    AzureADClientProps azureADClientProps;

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public ModelAndView login(HttpServletRequest request, HttpServletResponse response) throws ServletException,IOException {
        ModelAndView model = new ModelAndView();
        model.addObject("title", "Login Page");
        model.setViewName("login");
        return model;
    }

    @RequestMapping(value = {"/accessdenied"}, method = RequestMethod.GET)
    public ModelAndView accessDeniedPage() {
        ModelAndView model = new ModelAndView();
        model.addObject("message", "Either username or password is incorrect.");
        model.setViewName("accessdenied");
        return model;
    }

    @RequestMapping(value = {"/userlandingpage"}, method = RequestMethod.GET)
    public ModelAndView userPage(HttpServletRequest httpRequest) {

        ModelAndView model = new ModelAndView();
        model.addObject("title", "User Landing Page");
        model.addObject("user", getLoggedInUserName());
        model.addObject("userslist", getUsersList(httpRequest));
        model.setViewName("userlandingpage");
        return model;
    }


    private String getLoggedInUserName() {
        String userName = null;
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            userName = ((UserDetails) principal).getUsername();
        } else {
            userName = principal.toString();
        }
        return userName;
    }

    private ModelMap getUsersList(HttpServletRequest httpRequest){
        ModelMap model = new ModelMap();
        HttpSession session = httpRequest.getSession();
        AuthenticationResult result = (AuthenticationResult) session.getAttribute(AuthHelper.PRINCIPAL_SESSION_NAME);
        if (result == null) {
            model.addAttribute("error", new Exception("AuthenticationResult not found in session."));
        } else {
            String data;
            try {
                String tenant = azureADClientProps.getTenant();
                data = getUsersListFromGraph(result.getAccessToken(), azureADClientProps.getTenant());
                model.addAttribute("tenant", tenant);
                model.addAttribute("users", data);
                model.addAttribute("userInfo", result.getUserInfo());
            } catch (Exception e) {
                model.addAttribute("error", e);
            }
        }
        return model;
    }



    private String getUsersListFromGraph(String accessToken, String tenant) throws Exception {
        URL url = new URL(String.format("https://graph.windows.net/%s/users?api-version=1.6", tenant,
                accessToken));

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("Authorization", accessToken);
        conn.setRequestProperty("Accept", "application/json");
        String goodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);
        // logger.info("goodRespStr ->" + goodRespStr);
        int responseCode = conn.getResponseCode();
        JSONObject response = HttpClientHelper.processGoodRespStr(responseCode, goodRespStr);
        JSONArray users;

        users = JSONHelper.fetchDirectoryObjectJSONArray(response);

        StringBuilder builder = new StringBuilder();
        User user;
        for (int i = 0; i < users.length(); i++) {
            JSONObject thisUserJSONObject = users.getJSONObject(i);
            user = new User();
            JSONHelper.convertJSONObjectToDirectoryObject(thisUserJSONObject, user);
            builder.append(user.getUserPrincipalName() + "<br/>");
        }
        return builder.toString();
    }

}
