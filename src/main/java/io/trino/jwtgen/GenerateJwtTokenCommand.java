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
import picocli.CommandLine;

import java.security.Key;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;

import static io.jsonwebtoken.security.Keys.hmacShaKeyFor;
import static java.nio.charset.StandardCharsets.UTF_8;

@CommandLine.Command(
        name = "generate_jwt_token",
        usageHelpAutoWidth = true
)
public class GenerateJwtTokenCommand
        implements Runnable
{
    private static final Serializer<Map<String, ?>> JWT_SERIALIZER = new JacksonSerializer<>();

    @CommandLine.Option(names = "--secret", required = true, description = "Secret value to generate JWT token from")
    public String secret;

    @CommandLine.Option(names = "--principal", defaultValue = "nodeId", required = true, description = "Value for subject to use for JWT token")
    public String principal;

    private GenerateJwtTokenCommand() {}

    @Override
    public void run()
    {
        System.out.println(generateJwt());
    }

    private String generateJwt()
    {
        return newJwtBuilder()
                .signWith(generateKey())
                .setSubject(principal)
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(5).toInstant()))
                .compact();
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
}
