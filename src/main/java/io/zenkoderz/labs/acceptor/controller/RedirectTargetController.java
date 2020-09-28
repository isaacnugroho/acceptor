/*
 * Copyright 2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.zenkoderz.labs.acceptor.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.views.View;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.base64.Base64;
import io.netty.handler.codec.base64.Base64Dialect;
import io.netty.util.CharsetUtil;
import io.reactivex.Flowable;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import javax.inject.Inject;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.lang3.RandomStringUtils;

@Controller()
public class RedirectTargetController {

  final static String hydraUrl = "http://localhost:4444";
  final static String authPath = "/oauth2/auth";
  final static String tokenPath = "/oauth2/token";
  final static String revokePath = "/oauth2/revoke";
  final static String userInfoPath = "/userinfo";
  final static String logoutPath = "/oauth2/sessions/logout";
  final String redirectUri = "http://localhost:11111/login-success";
  final String logoutUri = "http://localhost:11111/logout-success";

  final String clientId = "acceptor";
  final String grantType = "authorization_code";
  final String[] scope = {"openid", "offline"};
  final String responseType = "code";
  final String codeChallengeMethod = "S256";
  final Map<String, AuthenticationObject> sessions = new ConcurrentHashMap<>();
  final private MessageDigest messageDigest;
  final private ObjectMapper objectMapper;
  final private ObjectWriter prettyWriter;
  @Client(hydraUrl)
  @Inject
  HttpClient httpClient;

  public RedirectTargetController() throws NoSuchAlgorithmException {
    objectMapper = new ObjectMapper();
    prettyWriter = objectMapper.writerWithDefaultPrettyPrinter();
    messageDigest = MessageDigest.getInstance("SHA-256");
  }

  @View("home")
  @Get
  public HttpResponse<?> home() {
    return doResponse();
  }

  @View("home")
  @Get(value = "/login-success")
  public HttpResponse<?> loginSuccess(final HttpRequest<String> request) {
    final String code = request.getParameters().get("code");
    final String state = request.getParameters().get("state");
    final AuthenticationObject authenticationObject = sessions.get(state);

    if (authenticationObject == null) {
      return doResponse();
    }
    if (code == null) {
      authenticationObject.setFailed(true);
      return doResponse();
    }
    authenticationObject.setCodeToken(code);
    requestToken(authenticationObject, false);
    return retrieveUserInfo(state);
  }

  @View("home")
  @Get(value = "/refresh-token/{state}")
  public HttpResponse<?> refreshToken(@Parameter("state") final String state) {
    final AuthenticationObject authenticationObject = sessions.get(state);
    if (authenticationObject == null || !authenticationObject.isConnected() || authenticationObject
        .isEnded()) {
      return doResponse();
    }

    requestToken(authenticationObject, true);
    return doResponse();
  }

  @View("home")
  @Get(value = "/logout/{state}")
  public HttpResponse<?> logout(@Parameter("state") final String state) {
    final AuthenticationObject authenticationObject = sessions.get(state);
    if (authenticationObject == null || !authenticationObject.isConnected() || authenticationObject
        .isEnded()) {
      return doResponse();
    }

    MutableHttpRequest<?> mutableHttpRequest = HttpRequest.GET(logoutPath + "?state=" + state +
        "&id_token_hint=" + authenticationObject.getIdToken() +
        "&post_logout_redirect_uri=" + URLEncoder.encode(logoutUri, CharsetUtil.UTF_8))
        .accept(MediaType.APPLICATION_JSON);
    mutableHttpRequest.header("Authorization", "Bearer " + authenticationObject.getAccessToken());
    doExchange(authenticationObject, mutableHttpRequest);
    return doResponse();
  }

  @View("home")
  @Get(value = "/revoke/{state}")
  public HttpResponse<?> revoke(@Parameter("state") final String state) {
    final AuthenticationObject authenticationObject = sessions.get(state);
    if (authenticationObject == null || !authenticationObject.isConnected() || authenticationObject
        .isEnded()) {

      return doResponse();
    }
    ByteBuf encodedData = Unpooled.wrappedBuffer(messageDigest.digest(
        (authenticationObject.getClientId() + ":" + authenticationObject.getSubject()).getBytes()));
    ByteBuf encoded = Base64.encode(encodedData, Base64Dialect.URL_SAFE);
    final String basic = encoded.toString(CharsetUtil.UTF_8);

    Map<CharSequence, CharSequence> data = new HashMap<>();
    data.put("token", authenticationObject.getRefreshToken());
    data.put("token_type_hint", "refresh_token");
    data.put("client_id", authenticationObject.getClientId());

    MutableHttpRequest<?> mutableHttpRequest = HttpRequest.POST(revokePath, data)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .accept(MediaType.APPLICATION_JSON_TYPE);

    mutableHttpRequest.header("Authorization", "Basic " + basic);
    doExchange(authenticationObject, mutableHttpRequest);
    return doResponse();
  }

  @View("home")
  @Get(value = "/logout-success")
  public HttpResponse<?> logoutSuccess(final HttpRequest<String> request) {
    final String state = request.getParameters().get("state");

    final AuthenticationObject authenticationObject = sessions.get(state);
    if (authenticationObject == null || !authenticationObject.isConnected() || authenticationObject
        .isEnded()) {
      return doResponse();
    }
    authenticationObject.setEnded(true);
    return doResponse();
  }

  private void doExchange(final AuthenticationObject authenticationObject,
      final HttpRequest<?> mutableHttpRequest) {
    try {
      Flowable<HttpResponse<String>> call = Flowable
          .fromPublisher(httpClient.exchange(mutableHttpRequest, String.class));
      HttpResponse<String> httpResponse = call.blockingSingle();

      constructResponse(httpResponse, authenticationObject);
    } catch (Exception e) {
      try (StringWriter stringWriter = new StringWriter(); PrintWriter writer = new PrintWriter(
          stringWriter)) {
        e.printStackTrace(writer);
        authenticationObject.setResponseJson(stringWriter.toString());
      } catch (Exception ex) {
        // do nothing;
      }
    }

  }

  private void requestToken(final AuthenticationObject authenticationObject,
      final boolean refresh) {
    Map<CharSequence, CharSequence> data = new HashMap<>();
    data.put("client_id", clientId);

    if (refresh) {
      if (authenticationObject.getRefreshToken() == null) {
        return;
      }
      data.put("refresh_token", authenticationObject.getRefreshToken());
      data.put("grant_type", "refresh_token");
    } else {
      data.put("redirect_uri", redirectUri);
      data.put("grant_type", grantType);
      data.put("code_verifier", authenticationObject.getCodeVerifier());
      data.put("code", authenticationObject.getCodeToken());
      data.put("client_secret", null);
    }

    MutableHttpRequest<?> mutableHttpRequest = HttpRequest.POST(tokenPath, data)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .accept(MediaType.APPLICATION_JSON_TYPE);
    HttpResponse<String> httpResponse;
    try {
      Flowable<HttpResponse<String>> call = Flowable
          .fromPublisher(httpClient.exchange(mutableHttpRequest, String.class));
      httpResponse = call.blockingSingle();
    } catch (Exception e) {
      try (StringWriter stringWriter = new StringWriter(); PrintWriter writer = new PrintWriter(
          stringWriter)) {
        e.printStackTrace(writer);
        authenticationObject.setResponseJson(stringWriter.toString());
      } catch (Exception ex) {
        // do nothing;
      }
      return;
    }

    constructResponse(httpResponse, authenticationObject);

    if (!httpResponse.getStatus().equals(HttpStatus.OK)) {
      authenticationObject.setFailed(true);
      return;
    }

    httpResponse.getBody().ifPresent(body -> {
      try {
        JsonNode jsonNode = objectMapper.readTree(body);
        authenticationObject.setAccessToken(getValue(jsonNode, "access_token"));
        authenticationObject.setIdToken(getValue(jsonNode, "id_token"));
        authenticationObject.setTokenType(getValue(jsonNode, "token_type"));
        authenticationObject.setScope(getValue(jsonNode, "scope"));
        authenticationObject.setRefreshToken(getValue(jsonNode, "refresh_token"));
        final String ttl = getValue(jsonNode, "expires_in");
        if (StringUtils.isNotEmpty(ttl)) {
          authenticationObject.setExpiresIn(Long.parseLong(ttl));
        }
        authenticationObject.setConnected(true);
      } catch (JsonProcessingException e) {
        authenticationObject.setFailed(true);
        // do nothing
      }
    });
  }

  private String getValue(final JsonNode node, final String name) {
    if (node.has(name)) {
      return node.get(name).asText();
    }
    return null;
  }

  @View("home")
  @Get(value = "/user-info/{state}")
  public HttpResponse<?> retrieveUserInfo(@Parameter("state") final String state) {
    final AuthenticationObject authenticationObject = sessions.get(state);
    if (authenticationObject == null || !authenticationObject.isConnected() || authenticationObject
        .isEnded()) {
      return doResponse();
    }
    MutableHttpRequest<?> mutableHttpRequest = HttpRequest.GET(userInfoPath)
        .accept(MediaType.APPLICATION_JSON);
    mutableHttpRequest.header("Authorization", "Bearer " + authenticationObject.getAccessToken());
    Flowable<HttpResponse<String>> call = Flowable
        .fromPublisher(httpClient.exchange(mutableHttpRequest, String.class));
    HttpResponse<String> httpResponse = call.blockingSingle();

    constructResponse(httpResponse, authenticationObject);

    httpResponse.getBody().ifPresent(body -> {
      try {
        JsonNode jsonNode = objectMapper.readTree(body);
        authenticationObject.setSubject(jsonNode.get("sub").asText());
        authenticationObject.setUserInfoJson(prettyWriter.writeValueAsString(jsonNode));

      } catch (JsonProcessingException e) {
        authenticationObject.setUserInfoJson(body);
      }
    });

    return doResponse();
  }

  private void constructResponse(final HttpResponse<?> httpResponse,
      final AuthenticationObject authenticationObject) {

    authenticationObject.setTimeStamp(Instant.now(Clock.systemUTC()).toEpochMilli());

    final Response response = Response.builder()
        .headers(httpResponse.getHeaders().asMap(String.class, String.class))
        .httpStatus(httpResponse.status())
        .build();

    if (httpResponse.body() != null) {
      try {
        final String body = (String) httpResponse.body();
        JsonNode jsonNode = objectMapper.readTree(body);
        response.setBody(jsonNode);
      } catch (JsonProcessingException e) {
        response.setBody(httpResponse.body());
      }
      try {
        final String json = prettyWriter.writeValueAsString(response);
        authenticationObject.setResponseJson(json);
      } catch (JsonProcessingException e) {
        // do nothing
      }
    }
  }

  private HttpResponse<?> doResponse() {
    createNewAuthenticationObject();
    return HttpResponse.ok(CollectionUtils.mapOf(
        "sessions", sessions.values().stream()
            .sorted(Comparator.comparingLong(o -> -o.getTimeStamp()))
            .collect(Collectors.toList())));
  }

  private void createNewAuthenticationObject() {
    if (!sessions.isEmpty() && sessions.values().stream()
        .anyMatch(s -> !s.isConnected() && !s.isEnded() && !s.isFailed())) {
      return;
    }

    final String codeVerifier = RandomStringUtils.randomAlphanumeric(80);
    final String state = RandomStringUtils.randomAlphanumeric(10);

    ByteBuf encodedData = Unpooled.wrappedBuffer(messageDigest.digest(codeVerifier.getBytes()));
    ByteBuf encoded = Base64.encode(encodedData, Base64Dialect.URL_SAFE);
    final String codeChallenge = encoded.toString(CharsetUtil.UTF_8)
        .replace("=", "").replace("+", "-").replace("/", "_");

    // login will be done at browser. Remember to clear cookies for new login
    final String uri = String.format("%s?response_type=%s&state=%s&client_id=%s" +
            "&scope=%s&redirect_uri=%s&code_challenge_method=%s&code_challenge=%s&lang=id",
        hydraUrl + authPath, responseType, state, clientId,
        URLEncoder.encode(String.join(" ", scope), CharsetUtil.UTF_8),
        URLEncoder.encode(redirectUri, CharsetUtil.UTF_8), codeChallengeMethod, codeChallenge);

    sessions.computeIfAbsent(state, s -> AuthenticationObject.builder()
        .clientId(clientId)
        .state(s)
        .statusJson("Not logged in")
        .codeChallenge(codeChallenge)
        .codeVerifier(codeVerifier)
        .loginUri(uri)
        .timeStamp(Instant.now(Clock.systemDefaultZone()).toEpochMilli())
        .build());
  }

  @Getter
  @Setter
  @ToString(doNotUseGetters = true)
  @Builder(toBuilder = true)
  public static class Response {

    private Map<String, String> headers;
    private HttpStatus httpStatus;
    private Object body;
  }

  @Getter
  @Setter
  @ToString(doNotUseGetters = true)
  @Builder(toBuilder = true)
  public static class AuthenticationObject {
    public String clientId;
    public String subject;
    public String state;
    public String codeChallenge;
    public String codeVerifier;
    public String codeToken;
    public String idToken;
    public String refreshToken;
    public long expiresIn;
    public String accessToken;
    public String tokenType;
    public String scope;
    public String loginUri;
    public String logoutUri;
    public String refreshTokenUri;
    public boolean failed;
    public boolean connected;
    public boolean ended;
    public long timeStamp;
    public String statusJson;
    public String responseJson;
    public String userInfoJson;
  }
}
