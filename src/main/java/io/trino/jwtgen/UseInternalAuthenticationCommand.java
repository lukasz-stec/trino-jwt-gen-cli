/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.jwtgen;

import com.google.common.hash.Hashing;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.trino.client.JsonCodec;
import io.trino.client.JsonResponse;
import io.trino.client.QueryResults;
import io.trino.client.ServerInfo;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import picocli.CommandLine;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Key;
import java.sql.SQLException;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;

import static com.google.common.net.HttpHeaders.ACCEPT_ENCODING;
import static io.jsonwebtoken.security.Keys.hmacShaKeyFor;
import static io.trino.client.JsonCodec.jsonCodec;
import static io.trino.client.OkHttpUtil.setupInsecureSsl;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.nio.charset.StandardCharsets.UTF_8;

@CommandLine.Command(
        name = "use_internal_authentication",
        usageHelpAutoWidth = true
)
public class UseInternalAuthenticationCommand
    implements Runnable
{
    private static final MediaType MEDIA_TYPE_TEXT = MediaType.parse("text/plain; charset=utf-8");
    private static final String TRINO_INTERNAL_BEARER = "X-Trino-Internal-Bearer";
    private static final JsonCodec<QueryResults> QUERY_RESULTS_CODEC = jsonCodec(QueryResults.class);
    private static final JsonCodec<ServerInfo> SERVER_INFO_CODEC = jsonCodec(ServerInfo.class);
    private static final Serializer<Map<String, ?>> JWT_SERIALIZER = new JacksonSerializer<>();

    @CommandLine.Option(names = "--secret", required = false, description = "Secret value to generate JWT token from")
    public String secret;

    @CommandLine.Option(names = "--principal", defaultValue = "nodeId", required = true, description = "Value for subject to use for JWT token")
    public String principal;

    @CommandLine.Option(names = "--coordinator", required = true, description = "Coordinator URL")
    public String coordinatorUrl;

    private UseInternalAuthenticationCommand() {}

    @Override
    public void run()
    {
        try {
            String jwt = generateJwt();
            System.out.println("generated JWT");
            System.out.println(jwt);
            testShowCatalogs(jwt);
        }
        catch (SQLException e) {
            System.out.println(e);
        }
        catch (URISyntaxException uriSyntaxException) {
            System.out.println("invalid coordinator url: " + coordinatorUrl);
            System.out.println(uriSyntaxException);
        }
    }

    private String generateJwt()
            throws URISyntaxException
    {
        return newJwtBuilder()
                .signWith(generateKey())
                .setSubject(principal)
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(5).toInstant()))
                .compact();
    }

    private void testShowCatalogs(String jwt)
            throws URISyntaxException, SQLException
    {
        OkHttpClient httpClient = buildHttpClient();
        URI uri = new URI(coordinatorUrl);
        Request request = buildShowCatalogsRequest(uri, jwt);
        JsonResponse<QueryResults> response = JsonResponse.execute(QUERY_RESULTS_CODEC, httpClient, request);
        if ((response.getStatusCode() != HTTP_OK) || !response.hasValue()) {
            throw new SQLException("show catalogs failed");
        }
        QueryResults results = response.getValue();
        System.out.println(results.getColumns());
        URI nextUri = results.getNextUri();
        while (nextUri != null) {
            request = prepareRequest(HttpUrl.get(nextUri)).build();
            response = JsonResponse.execute(QUERY_RESULTS_CODEC, httpClient, request);
            results = response.getValue();
            System.out.println(results.getData());
            nextUri = results.getNextUri();
        }
    }

    private OkHttpClient buildHttpClient()
    {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        setupInsecureSsl(builder);
        return builder.build();
    }

    private Request buildShowCatalogsRequest(URI coordinatorUri, String jwt)
    {
        String query = "show catalogs";
        HttpUrl url = HttpUrl.get(coordinatorUri);
        url = url.newBuilder().encodedPath("/v1/statement").build();
        Request.Builder builder = prepareInitialRequest(url, jwt)
                .post(RequestBody.create(MEDIA_TYPE_TEXT, query));
        return builder.build();
    }

    private Request.Builder prepareInitialRequest(HttpUrl url, String jwt)
    {
        Request.Builder builder = new Request.Builder()
                .addHeader(TRINO_INTERNAL_BEARER, jwt)
                .url(url);
        builder.header(ACCEPT_ENCODING, "identity");
        return builder;
    }

    private Request.Builder prepareRequest(HttpUrl url)
    {
        Request.Builder builder = new Request.Builder()
                .url(url);
        builder.header(ACCEPT_ENCODING, "identity");
        return builder;
    }

    private Key generateKey()
            throws URISyntaxException
    {
        if (secret != null) {
            return hmacShaKeyFor(Hashing.sha256().hashString(secret, UTF_8).asBytes());
        }
        return hmacShaKeyFor(Hashing.sha256().hashString(getEnvironment(), UTF_8).asBytes());
    }

    private String getEnvironment()
            throws URISyntaxException
    {
        OkHttpClient httpClient = buildHttpClient();
        URI uri = new URI(coordinatorUrl);
        HttpUrl url = HttpUrl.get(uri);
        url = url.newBuilder().encodedPath("/v1/info").build();
        Request.Builder builder = new Request.Builder()
                .url(url);
        Request request = builder.build();
        JsonResponse<ServerInfo> response = JsonResponse.execute(SERVER_INFO_CODEC, httpClient, request);
        if ((response.getStatusCode() != HTTP_OK) || !response.hasValue()) {
            // handle error
        }
        System.out.println(coordinatorUrl + " has environment " + response.getValue().getEnvironment());
        return response.getValue().getEnvironment();
    }

    private static JwtBuilder newJwtBuilder()
    {
        return new DefaultJwtBuilder()
                .serializeToJsonWith(JWT_SERIALIZER);
    }
}
