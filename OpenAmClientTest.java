package nz.co.vodafone.identity.externalservices.openam;

import nz.co.vodafone.identity.externalservices.*;
import nz.co.vodafone.identity.externalservices.openam.model.*;
import nz.co.vodafone.token.Info;
import nz.co.vodafone.token.InvalidTokenException;
import nz.co.vodafone.token.Token;
import nz.co.vodafone.token.TokenizerResource;
import nz.co.vodafone.token.rest.client.TokenRestClient;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.util.ReflectionTestUtils;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static shiver.me.timbers.data.random.RandomStrings.someString;

/**
 * Created by raykovr on 13/06/17.
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenAmClientTest {

    private Logger log = LoggerFactory.getLogger(getClass());

    private static final String ACTION_PARAMETER = "_action";
    private static final String TOKEN_HEADER = "iPlanetDirectoryPro";
    private static final String USERNAME_HEADER = "X-OpenAM-Username";
    private static final String PASSWORD_HEADER = "X-OpenAM-Password";
    private static final Entity EMPTY_BODY = Entity.json("");

    @Mock
    private Client client;

    @Mock
    WebTarget webTarget;

    @Mock
    Invocation.Builder invocationBuilder;

    @Mock
    private TokenRestClient tokenClient;

    @Mock
    private Token token;

    @Mock
    OpenAmResponseFactories responseFactories;

    @Mock
    OpenAMResponseModelFactory openAMResponseModelFactory;

    @Mock
    Response response;

    @Mock
    LoginResponse loginResponse;

    @Mock
    LogoutResponse logoutResponse;

    @Mock
    ValidateResponse validateResponse;

    @Mock
    AttributesResponse attributesResponse;

    @Mock
    GetTokenResponseBean getTokenResponseBean;

    @InjectMocks
    private OpenAmClient openAmClient;

    @Before
    public void setUp() throws Exception {
        URI uri = new URI("http://localhost:7012");
        ReflectionTestUtils.setField(openAmClient, "baseUrl", uri);
        ReflectionTestUtils.setField(openAmClient, "authenticatePath", "/openam/json/authenticate");
        ReflectionTestUtils.setField(openAmClient, "authIndexType", "module");
        ReflectionTestUtils.setField(openAmClient, "authIndexValue", "LDAPCustomLogin");
        ReflectionTestUtils.setField(openAmClient, "logoutPath", "/openam/json/sessions");
        ReflectionTestUtils.setField(openAmClient, "validatePath", "/openam/json/sessions/{token}");
        ReflectionTestUtils.setField(openAmClient, "attributePath", "/openam/json/users/{username}");
        ReflectionTestUtils.setField(openAmClient, "flexRealm", "FlexLogin");
        ReflectionTestUtils.setField(openAmClient, "passwordRealm", "PasswordTokenGeneration");
        ReflectionTestUtils.setField(openAmClient, "flexAuthIndexValue", "FlexLoginService");
        ReflectionTestUtils.setField(openAmClient, "passAuthIndexValue", "PasswordTokenService");
        ReflectionTestUtils.setField(openAmClient, "csrAuthIndexValue", "CSRLoginService");

        when(client.target(uri)).thenReturn(webTarget);
        when(webTarget.request(APPLICATION_JSON)).thenReturn(invocationBuilder);
        when(invocationBuilder.accept(APPLICATION_JSON)).thenReturn(invocationBuilder);

        when(responseFactories.getResponseModelFactory(LoginResponse.class)).thenReturn(openAMResponseModelFactory);
        when(responseFactories.getResponseModelFactory(LogoutResponse.class)).thenReturn(openAMResponseModelFactory);
        when(responseFactories.getResponseModelFactory(AttributesResponse.class)).thenReturn(openAMResponseModelFactory);
        when(responseFactories.getResponseModelFactory(ValidateResponse.class)).thenReturn(openAMResponseModelFactory);
        when(responseFactories.getResponseModelFactory(GetTokenResponse.class)).thenReturn(openAMResponseModelFactory);
    }

    @Test
    public void login() throws Exception {
        String username = someString(20);
        String password = someString(20);
        String tokenId = someString(20);

        when(webTarget.path("/openam/json/authenticate")).thenReturn(webTarget);
        when(webTarget.queryParam("authIndexType", "module")).thenReturn(webTarget);
        when(webTarget.queryParam("authIndexValue", "LDAPCustomLogin")).thenReturn(webTarget);
        when(invocationBuilder.header(USERNAME_HEADER, username)).thenReturn(invocationBuilder);
        when(invocationBuilder.header(PASSWORD_HEADER, password)).thenReturn(invocationBuilder);
        when(invocationBuilder.post(EMPTY_BODY, Response.class)).thenReturn(response);

        when(openAMResponseModelFactory.readResponse(LoginResponseBean.class, response)).thenReturn(loginResponse);
        when(loginResponse.getTokenId()).thenReturn(tokenId);

        LoginResponse actual = openAmClient.login(username, password);

        assertThat(actual.getTokenId()).isEqualTo(tokenId);
    }


    @Test
    public void logout() throws Exception {
        String token = someString(20);
        String OK = "OK";

        when(webTarget.path("/openam/json/sessions")).thenReturn(webTarget);
        when(webTarget.queryParam(ACTION_PARAMETER, "logout")).thenReturn(webTarget);
        when(invocationBuilder.header(TOKEN_HEADER, token)).thenReturn(invocationBuilder);
        when(invocationBuilder.post(EMPTY_BODY, Response.class)).thenReturn(response);

        when(openAMResponseModelFactory.readResponse(LogoutResponseBean.class, response)).thenReturn(logoutResponse);
        when(logoutResponse.getResult()).thenReturn(OK);

        LogoutResponse actual = openAmClient.logout(token);

        assertThat(actual.getResult()).isEqualTo(OK);
    }

    @Test
    public void validate() throws Exception {
        String token = someString(20);
        boolean valid = true;

        when(webTarget.path("/openam/json/sessions/{token}")).thenReturn(webTarget);
        when(webTarget.queryParam(ACTION_PARAMETER, "validate")).thenReturn(webTarget);
        when(webTarget.resolveTemplate("token", token)).thenReturn(webTarget);
        when(invocationBuilder.post(EMPTY_BODY, Response.class)).thenReturn(response);

        when(openAMResponseModelFactory.readResponse(ValidateResponseBean.class, response)).thenReturn(validateResponse);
        when(validateResponse.isValid()).thenReturn(valid);

        ValidateResponse actual = openAmClient.validate(token);

        assertThat(actual.isValid()).isTrue();
    }

    @Test
    public void getAttributes() throws Exception {
        String token = someString(20);
        String uid = someString(20);
        String fieldList = someString(20);

        Map map = mock(Map.class);

        when(webTarget.path("/openam/json/users/{username}")).thenReturn(webTarget);
        when(webTarget.queryParam("_fields", fieldList)).thenReturn(webTarget);
        when(webTarget.resolveTemplate("username", uid)).thenReturn(webTarget);
        when(invocationBuilder.header(TOKEN_HEADER, token)).thenReturn(invocationBuilder);
        when(invocationBuilder.get()).thenReturn(response);

        when(openAMResponseModelFactory.readResponse(AttributesResponseBean.class, response)).thenReturn(attributesResponse);
        when(attributesResponse.getAttributes()).thenReturn(map);

        AttributesResponse actual = openAmClient.getAttributes(token, uid, fieldList);

        assertThat(actual.getAttributes()).isEqualTo(map);
    }

    @Test
    public void getEmailVerificationToken() throws Exception {
        String username = someString(20);
        String tokenId = someString(20);

        when(tokenClient.create(username, TokenizerResource.Stereotype.EMAIL_VERIFICATION, username)).thenReturn(token);
        when(token.getToken()).thenReturn(tokenId);

        /*GetTokenResponse actual = openAmClient.requestEmailToken(username);

        assertThat(actual.getTokenId()).isEqualTo(tokenId);
        verify(tokenClient).create(username, TokenizerResource.Stereotype.EMAIL_VERIFICATION, username);*/
    }

    @Test
    public void getPasswordResetToken() throws Exception {
        String username = someString(20);
        String tokenId = someString(20);

        when(webTarget.path("/openam/json/authenticate")).thenReturn(webTarget);
        when(webTarget.queryParam("authIndexType", "module")).thenReturn(webTarget);
        when(webTarget.queryParam("authIndexValue", "PasswordTokenService")).thenReturn(webTarget);
        when(webTarget.queryParam("realm", "PasswordTokenGeneration")).thenReturn(webTarget);
        when(invocationBuilder.header(USERNAME_HEADER, username)).thenReturn(invocationBuilder);
        when(invocationBuilder.post(Entity.json(""))).thenReturn(response);

        when(openAMResponseModelFactory.readResponse(GetTokenResponseBean.class, response)).thenReturn(getTokenResponseBean);
        when(getTokenResponseBean.getTokenId()).thenReturn(tokenId);

        GetTokenResponse actual = openAmClient.getPasswordResetToken(username);

        assertThat(actual.getTokenId()).isEqualTo(tokenId);
        //verify(tokenClient).create(username, TokenizerResource.Stereotype.RESET_PASSWORD, username);
    }

    @Test
    public void authoriseModifyToken() throws Exception {
        String username = someString(20);
        String tokenId = someString(20);

        Info info = mock(Info.class);
        TokenizerResource.Stereotype stereotype = TokenizerResource.Stereotype.EMAIL_VERIFICATION;
        when(tokenClient.info(tokenId)).thenReturn(info);
        when(info.getStereotype()).thenReturn(stereotype);
        when(tokenClient.retrieve(String.class, tokenId, stereotype)).thenReturn(username);

        openAmClient.authoriseModifyToken(tokenId);

        verify(tokenClient).info(tokenId);
        verify(tokenClient).retrieve(String.class, tokenId, stereotype);
    }

    @Test(expected = nz.co.vodafone.exceptions.InvalidTokenException.class)
    public void authoriseModifyTokenInvalidToken() throws Exception {
        String username = someString(20);
        String tokenId = someString(20);

        Info info = mock(Info.class);
        TokenizerResource.Stereotype stereotype = TokenizerResource.Stereotype.EMAIL_VERIFICATION;
        when(tokenClient.info(tokenId)).thenReturn(info);
        when(info.getStereotype()).thenReturn(stereotype);
        when(tokenClient.retrieve(String.class, tokenId, stereotype)).thenThrow(InvalidTokenException.class);

        try {
            openAmClient.authoriseModifyToken(tokenId);
        } catch (nz.co.vodafone.exceptions.InvalidTokenException e) {
            verify(tokenClient).info(tokenId);
            verify(tokenClient).retrieve(String.class, tokenId, stereotype);
            throw e;
        }
    }

    @Test
    public void confirmCredentials() throws Exception {
        String username = someString(20);
        String password = someString(20);
        String tokenId = someString(20);

        when(webTarget.path("/openam/json/authenticate")).thenReturn(webTarget);
        when(webTarget.queryParam("authIndexType", "module")).thenReturn(webTarget);
        when(webTarget.queryParam("authIndexValue", "LDAPCustomLogin")).thenReturn(webTarget);
        when(invocationBuilder.header(USERNAME_HEADER, username)).thenReturn(invocationBuilder);
        when(invocationBuilder.header(PASSWORD_HEADER, password)).thenReturn(invocationBuilder);
        when(invocationBuilder.post(EMPTY_BODY, Response.class)).thenReturn(response);

        when(openAMResponseModelFactory.readResponse(LoginResponseBean.class, response)).thenReturn(loginResponse);
        when(loginResponse.getTokenId()).thenReturn(tokenId);

        LoginResponse actual = openAmClient.confirmCredentials(username, password);

        assertThat(actual.getTokenId()).isEqualTo(tokenId);
    }


}