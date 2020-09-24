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
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.core.util.CollectionUtils;
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
import io.zenkoderz.labs.acceptor.Application;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.inject.Inject;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller()
public class RedirectTargetController {

  final static String authUrl = "http://localhost:4444/oauth2/auth";
  final static String tokenUrl = "http://localhost:4444/oauth2/token";
  final String redirectUri = "http://localhost:11111/accept";

  final String clientId = "acceptor";
  final String grantType = "authorization_code";
  final String[] scope = {"openid", "offline"};
  final String responseType = "code";
  final String codeChallengeMethod = "S256";

  final Map<String, String> codeVerifiers = new HashMap<>();

  final Logger logger = LoggerFactory.getLogger(Application.class);

  @Client(tokenUrl)
  @Inject
  HttpClient httpClient;

  @View("home")
  @Get()
  public HttpResponse<?> home() {

    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");

      final String codeVerifier = RandomStringUtils.randomAlphanumeric(80);
      final String state = RandomStringUtils.randomAlphanumeric(10);

      ByteBuf encodedData = Unpooled.wrappedBuffer(digest.digest(codeVerifier.getBytes()));
      ByteBuf encoded = Base64.encode(encodedData, Base64Dialect.URL_SAFE);
      final String codeChallenge = encoded.toString(CharsetUtil.UTF_8)
          .replace("=", "").replace("+", "-").replace("/", "_");

      final String uri = String.format("%s?response_type=%s&state=%s&client_id=%s" +
              "&scope=%s&redirect_uri=%s&code_challenge_method=%s&code_challenge=%s",
          authUrl, responseType, state, clientId,
          URLEncoder.encode(String.join(" ", scope), CharsetUtil.UTF_8),
          URLEncoder.encode(redirectUri, CharsetUtil.UTF_8), codeChallengeMethod, codeChallenge);
      logger.info(uri);
      codeVerifiers.put(state, codeVerifier);
      return HttpResponse.ok(CollectionUtils.mapOf("target", uri));

    } catch (NoSuchAlgorithmException e) {
      final StringWriter buffer = new StringWriter();
      final PrintWriter writer = new PrintWriter(buffer, true);
      e.printStackTrace(writer);
      final String result = buffer.toString();
      try {
        writer.close();
        buffer.close();
      } catch (IOException ioException) {
        // do nothing
      }
      return HttpResponse.serverError(result);
    }
  }

  @View("payload")
  @Get(value = "/accept")
  public HttpResponse<?> index(final HttpRequest<String> request) throws JsonProcessingException {
    final String code = request.getParameters().get("code");
    final String state = request.getParameters().get("state");
    final String codeVerifier = codeVerifiers.get(state);

    if (code == null || codeVerifier == null) {
      return HttpResponse
          .ok(CollectionUtils.mapOf("payload", request.toString(), "error", "failed request"));
    }

    Map<CharSequence, CharSequence> data = new LinkedHashMap<>();
    data.put("grant_type", grantType);
    data.put("code", code);
    data.put("redirect_uri", redirectUri);
    data.put("code_verifier", codeVerifier);
    data.put("client_id", clientId);
    data.put("client_secret", null);

    MutableHttpRequest<?> mutableHttpRequest = HttpRequest.POST("", data)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED);
    Flowable<HttpResponse<String>> call = Flowable
        .fromPublisher(httpClient.exchange(mutableHttpRequest, String.class));
    HttpResponse<String> httpResponse = call.blockingSingle();

    Response response = Response.builder()
        .headers(httpResponse.getHeaders().asMap(String.class, String.class))
        .build();
    final ObjectMapper mapper = new ObjectMapper();
    httpResponse.getBody().ifPresent(body -> {
      try {
        response.setBody(mapper.readTree(body));
      } catch (JsonProcessingException e) {
        response.setBody(body);
      }
    });
    String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(response);
    return HttpResponse.ok(CollectionUtils.mapOf("payload", json));
  }

  @Getter
  @Setter
  @ToString(doNotUseGetters = true)
  @Builder(toBuilder = true)
  private static class Response {

    private Map<String, String> headers;
    private HttpStatus httpStatus;
    private Object body;
  }
}