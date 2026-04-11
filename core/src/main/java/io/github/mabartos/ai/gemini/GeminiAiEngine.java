package io.github.mabartos.ai.gemini;

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
 * Google Gemini AI engine implementation
 */
public class GeminiAiEngine implements AiEngine {
    private static final Logger logger = Logger.getLogger(GeminiAiEngine.class);

    private final HttpClientProvider httpClientProvider;

    public GeminiAiEngine(KeycloakSession session) {
        this.httpClientProvider = session.getProvider(HttpClientProvider.class);
    }

    @Override
    public <T> Optional<T> getResult(String context, String message, Class<T> clazz, DefaultAiDataRequest.ResponseFormat schema) {
        final var baseUrl = GeminiAiEngineFactory.getApiUrl();
        final var model = GeminiAiEngineFactory.getModel();
        final var apiKey = GeminiAiEngineFactory.getApiKey();

        if (baseUrl.isEmpty() || model.isEmpty() || apiKey.isEmpty()) {
            logger.warnf("Required environment variables for Gemini API are missing. Check the guide how to set this AI engine. Ignoring result");
            return Optional.empty();
        }

        var httpClient = Boolean.parseBoolean(System.getenv("INSECURE_SSL"))
            ? InsecureHttpClientUtil.create()
            : httpClientProvider.getHttpClient();

        // Gemini API key is passed as a query parameter in the URL
        String endpoint = String.format("%s/models/%s:generateContent?key=%s", baseUrl.get(), model.get(), apiKey.get());

        var geminiResponse = AiEngineUtils.aiEngineRequest(
                httpClient,
                endpoint,
                () -> GeminiApiRequest.create(context, message, schema),
                Map.of(),
                GeminiApiResponse.class
        );

        if (geminiResponse.isEmpty()) {
            return Optional.empty();
        }

        logger.tracef("Response from Gemini AI engine: %s\n", geminiResponse.get().toString());

        // If requesting GeminiApiResponse directly, return it
        if (clazz == GeminiApiResponse.class) {
            return Optional.of(clazz.cast(geminiResponse.get()));
        }

        // Otherwise, parse the text content as the requested type
        String text = geminiResponse.get().getText();
        if (text != null && !text.isEmpty()) {
            try {
                return Optional.of(JsonSerialization.readValue(text, clazz));
            } catch (IOException e) {
                logger.warnf("Cannot parse Gemini response as %s: %s", clazz.getName(), text);
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
            return Risk.invalid("No response from the Gemini API");
        }

        var riskData = response.get();
        logger.tracef("Gemini AI evaluated risk: %s. Reason: %s", riskData.risk(), riskData.reason());
        return Risk.of(riskData.risk(), riskData.reason());
    }

    @Override
    public void close() {
    }
}
