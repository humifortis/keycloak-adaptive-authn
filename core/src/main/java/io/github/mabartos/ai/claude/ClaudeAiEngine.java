package io.github.mabartos.ai.claude;

import io.github.mabartos.ai.AiEngineUtils;
import io.github.mabartos.ai.DefaultAiDataRequest;
import io.github.mabartos.ai.DefaultAiRiskData;
import io.github.mabartos.spi.ai.AiEngine;
import io.github.mabartos.spi.level.Risk;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import io.github.mabartos.util.InsecureHttpClientUtil;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * Claude (Anthropic) AI engine implementation
 */
public class ClaudeAiEngine implements AiEngine {
    private static final Logger logger = Logger.getLogger(ClaudeAiEngine.class);

    private final HttpClientProvider httpClientProvider;

    public ClaudeAiEngine(KeycloakSession session) {
        this.httpClientProvider = session.getProvider(HttpClientProvider.class);
    }

    @Override
    public <T> Optional<T> getResult(String context, String message, Class<T> clazz, DefaultAiDataRequest.ResponseFormat schema) {
        final var url = ClaudeAiEngineFactory.getApiUrl();
        final var model = ClaudeAiEngineFactory.getModel();
        final var apiKey = ClaudeAiEngineFactory.getApiKey();

        if (url.isEmpty() || model.isEmpty() || apiKey.isEmpty()) {
            logger.warnf("Required environment variables for Claude API are missing. Check the guide how to set this AI engine. Ignoring result");
            return Optional.empty();
        }

        var httpClient = Boolean.parseBoolean(System.getenv("INSECURE_SSL"))
            ? InsecureHttpClientUtil.create()
            : httpClientProvider.getHttpClient();
        boolean enableCaching = ClaudeAiEngineFactory.isCachingEnabled();

        // Use AiEngineUtils to handle the HTTP request
        var claudeResponse = AiEngineUtils.aiEngineRequest(
                httpClient,
                url.get(),
                () -> ClaudeApiRequest.create(
                        model.get(),
                        context,
                        message,
                        schema,
                        enableCaching
                ),
                Map.of(
                        "x-api-key", apiKey.get(),
                        "anthropic-version", ClaudeAiEngineFactory.getApiVersion()
                ),
                ClaudeApiResponse.class
        );

        if (claudeResponse.isEmpty()) {
            return Optional.empty();
        }

        logger.tracef("Response from Claude AI engine: %s\n", claudeResponse.get().toString());

        // If requesting ClaudeApiResponse directly, return it
        if (clazz == ClaudeApiResponse.class) {
            return Optional.of(clazz.cast(claudeResponse.get()));
        }

        // Otherwise, parse the text content as the requested type
        String text = claudeResponse.get().getText();
        if (text != null && !text.isEmpty()) {
            try {
                return Optional.of(JsonSerialization.readValue(text, clazz));
            } catch (IOException e) {
                logger.warnf("Cannot parse Claude response as %s: %s", clazz.getName(), text);
                return Optional.empty();
            }
        }

        return Optional.empty();
    }

    @Override
    public Risk getRisk(String context, String message) {
        var response = getResult(context, message, DefaultAiRiskData.class,
                DefaultAiDataRequest.newJsonResponseFormat("risk_evaluation", AiEngine.DEFAULT_RISK_SCHEMA));
        if (response.isEmpty()) {
            return Risk.invalid("No response from the Claude API");
        }

        var riskData = response.get();
        logger.tracef("Claude AI evaluated risk: %s. Reason: %s", riskData.risk(), riskData.reason());
        return Risk.of(riskData.risk(), riskData.reason());
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}
