package nz.co.vodafone.identity.externalservices.openam;

import nz.co.vodafone.exceptions.InvalidCredentialsException;
import nz.co.vodafone.identity.externalservices.*;
import nz.co.vodafone.identity.externalservices.openam.model.*;
import nz.co.vodafone.token.Info;
import nz.co.vodafone.token.InvalidTokenException;
import nz.co.vodafone.token.rest.client.TokenRestClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import java.net.URI;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

/**
 * Created by ashleyj on 13/02/17.
 */
@Component
public class OpenAmClient extends OpenAMExternalServiceClient implements OpenAMClientResource {
    private Logger log = LoggerFactory.getLogger(getClass());

    private static final String ACTION_PARAMETER = "_action";
    private static final String TOKEN_HEADER = "iPlanetDirectoryPro";
    private static final String USERNAME_HEADER = "X-OpenAM-Username";

    @Value("${openAmClient.baseURL:http://localhost:7012}")
    private URI baseUrl;

    @Value("${openAmClient.authenticatePath:/openam/json/authenticate}")
    private String authenticatePath;

    @Value("${openAmClient.logoutPath:/openam/json/sessions}")
    private String logoutPath;

    @Value("${openAmClient.validatePath:/openam/json/sessions/{token}}")
    private String validatePath;

    @Value("${openAmClient.attributePath:/openam/json/users/{username}}")
    private String attributePath;

    @Value("${openAmClient.authIndexType:module}")
    private String authIndexType;

    @Value("${openAmClient.authIndexValue:LDAPCustomLogin}")
    private String authIndexValue;

    @Value("${openAmClient.csrAuthIndexValue:CSRADModule}")
    private String csrAuthIndexValue;

    @Value("${openAmClient.flexAuthIndexValue:FlexLoginService}")
    private String flexAuthIndexValue;

    @Value("${openAmClient.authEmailIndexValue:EmailTokenService}")
    private String authEmailIndexValue;

    @Value("${openAmClient.passAuthIndexValue:PasswordTokenService}")
    private String passAuthIndexValue;

    @Value("${openAmClient.emailRealm:EmailTokenGeneration}")
    private String emailRealm;

    @Value("${openAmClient.flexRealm:FlexLogin}")
    private String flexRealm;

    @Value("${openAmClient.passwordRealm:PasswordTokenGeneration}")
    private String passwordRealm;

    @Value("${openAmClient.retryPolicy.numRetries:3}")
    private int numRetries;

    @Autowired
    private TokenRestClient tokenRestClient;

    @Autowired
    AttributesResponse attributesResponse;

    public LoginResponse login(String username, String password) {
        Response response = getClientWebTarget(baseUrl)
                .path(authenticatePath)
                .queryParam("authIndexType", authIndexType)
                .queryParam("authIndexValue", authIndexValue)
                .request(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .header(USERNAME_HEADER, username)
                .header(PASSWORD_HEADER, password)
                .post(EMPTY_BODY, Response.class);
        return translateResponse(getResponseFactory(LoginResponse.class), LoginResponseBean.class, response);
    }


    @Override
    public LogoutResponse logout(String token) {
        Response response = getClientWebTarget(baseUrl)
                .path(logoutPath)
                .queryParam(ACTION_PARAMETER, "logout")
                .request(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .header(TOKEN_HEADER, token)
                .post(EMPTY_BODY, Response.class);
        return translateResponse(getResponseFactory(LogoutResponse.class), LogoutResponseBean.class, response);
    }

    @Override
    public ValidateResponse validate(String token) {
        Response response = getClientWebTarget(baseUrl)
                .path(validatePath)
                .queryParam(ACTION_PARAMETER, "validate")
                .resolveTemplate("token", token)
                .request(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .post(EMPTY_BODY, Response.class);
        return translateResponse(getResponseFactory(ValidateResponse.class), ValidateResponseBean.class, response);
    }

    @Override
    public AttributesResponse getAttributes(String token, String uid, String fieldList) {
        Response response = getClientWebTarget(baseUrl)
                .path(attributePath)
                .resolveTemplate("username", uid)
                //.queryParam("_fields", fieldList)
                .request(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .header(TOKEN_HEADER, token)
                .get();
        attributesResponse = translateResponse(getResponseFactory(AttributesResponse.class), AttributesResponseBean.class, response);
        return attributesResponse;
    }

    /**
     * Get email verification token from OpenAM .
     *
     * @param username
     * @return
     */
    @Override
    public GetTokenResponse requestEmailToken(String username) {
        Response response = getClientWebTarget(baseUrl)
                .path(authenticatePath)
                .queryParam("authIndexType", authIndexType)
                .queryParam("authIndexValue", authEmailIndexValue)
                .queryParam("realm", emailRealm)
                .request(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .header(USERNAME_HEADER, username)
                .post(Entity.json(""));
        log.info(String.valueOf(response.getStatusInfo().getStatusCode()));
        GetTokenResponse responseBean = translateResponse(getResponseFactory(GetTokenResponse.class), GetTokenResponseBean.class, response);
        return responseBean;
    }

    @Override
    public GetTokenResponse getPasswordResetToken(String username) {
        Response response = getClientWebTarget(baseUrl)
                .path(authenticatePath)
                .queryParam("authIndexType", authIndexType)
                .queryParam("authIndexValue", passAuthIndexValue)
                .queryParam("realm", passwordRealm)
                .request(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .header(USERNAME_HEADER, username)
                .post(Entity.json(""));

        log.info("Reset password response is :", response.toString());
        GetTokenResponse responseBean =
                ((OpenAMResponseModelFactory<GetTokenResponse>) openAmResponseFactories.getResponseModelFactory(GetTokenResponse.class))
                        .readResponse(GetTokenResponseBean.class, response);
        return responseBean;
    }

    @Override
    public void authoriseModifyToken(String token) {
        Info info = tokenRestClient.info(token);
        try {
            tokenRestClient.retrieve(String.class, token, info.getStereotype());
        } catch (InvalidTokenException e) {
            throw new nz.co.vodafone.exceptions.InvalidTokenException(e.getMessage());
        }
    }

    @Override
    public LoginResponse confirmCredentials(String username, String password) {
        try {
            return login(username, password);
        } catch (InvalidCredentialsException e) {
            throw new InvalidCredentialsException("Incorrect password.");
        }
    }


}
