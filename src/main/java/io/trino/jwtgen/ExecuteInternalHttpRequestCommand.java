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
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import picocli.CommandLine;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;

import static com.google.common.net.HttpHeaders.ACCEPT_ENCODING;
import static io.jsonwebtoken.security.Keys.hmacShaKeyFor;
import static java.nio.charset.StandardCharsets.UTF_8;

@CommandLine.Command(
        name = "execute_http_request",
        usageHelpAutoWidth = true
)
public class ExecuteInternalHttpRequestCommand
        implements Runnable
{
    private static final String TRINO_INTERNAL_BEARER = "X-Trino-Internal-Bearer";
    private static final Serializer<Map<String, ?>> JWT_SERIALIZER = new JacksonSerializer<>();

    @CommandLine.Option(names = "--secret", required = true, description = "Secret value to generate JWT token from. Use the value of sharedSecret from sep config the environment if sharedSecret is not set")
    public String secret;

    @CommandLine.Option(names = "--principal", defaultValue = "nodeId", required = true, description = "Value for subject to use for JWT token")
    public String principal;

    @CommandLine.Option(names = "--request", required = true, description = "Request URL e.g. http://<coordinator>:8080/v1/service\n")
    public String requestUrl;

    private ExecuteInternalHttpRequestCommand() {}

    @Override
    public void run()
    {
        try {
            String jwt = generateJwt();
            System.out.println("generated JWT");
            System.out.println(jwt);

            Request.Builder builder = new Request.Builder()
                    .addHeader(TRINO_INTERNAL_BEARER, jwt)
                    .url(requestUrl)
                    .get();
            builder.header(ACCEPT_ENCODING, "identity");
            Request request = builder.build();
            OkHttpClient httpClient = buildHttpClient();
            Response response = httpClient.newCall(request).execute();

            System.out.printf("Got: %s, headers %s, body %s%n", response, response.headers(), response.body() != null ? response.body().string() : "");
        }
        catch (URISyntaxException uriSyntaxException) {
            throw new RuntimeException("invalid request: " + requestUrl);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
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

    private OkHttpClient buildHttpClient()
    {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        setupInsecureSsl(builder);
        return builder.build();
    }

    private Key generateKey()
    {
        return hmacShaKeyFor(Hashing.sha256().hashString(secret, UTF_8).asBytes());
    }

    private static JwtBuilder newJwtBuilder()
    {
        return new DefaultJwtBuilder()
                .serializeToJsonWith(JWT_SERIALIZER);
    }

    public static void setupInsecureSsl(OkHttpClient.Builder clientBuilder)
    {
        try {
            X509TrustManager trustAllCerts = new X509TrustManager()
            {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType)
                {
                    throw new UnsupportedOperationException("checkClientTrusted should not be called");
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType)
                {
                    // skip validation of server certificate
                }

                @Override
                public X509Certificate[] getAcceptedIssuers()
                {
                    return new X509Certificate[0];
                }
            };

            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, new TrustManager[] {trustAllCerts}, new SecureRandom());

            clientBuilder.sslSocketFactory(sslContext.getSocketFactory(), trustAllCerts);
            clientBuilder.hostnameVerifier((hostname, session) -> true);
        }
        catch (GeneralSecurityException e) {
            throw new RuntimeException("Error setting up SSL: " + e.getMessage(), e);
        }
    }
}
