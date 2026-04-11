package io.github.mabartos.evaluator.behavior;

import io.github.mabartos.spi.evaluator.AbstractRiskEvaluator;
import io.github.mabartos.spi.level.Risk;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

public class HumifortisRiskEvaluator extends AbstractRiskEvaluator {
    private static final Logger logger = Logger.getLogger(HumifortisRiskEvaluator.class);

    private static final String ENV_API_URL = "HUMIFORTIS_API_URL";
    private static final String ENV_API_KEY = "HUMIFORTIS_API_KEY";
    private static final String ENV_TIMEOUT_MS = "HUMIFORTIS_TIMEOUT_MS";
    private static final String ENV_REALM_AS_TENANT = "HUMIFORTIS_REALM_AS_TENANT";

    private static final String DEFAULT_API_URL = "https://api.humifortis.educosmic.tech";
    private static final int DEFAULT_TIMEOUT_MS = 2000;
    private static final String FAIL_OPEN_REASON = "Humifortis unavailable - fail open";

    private final CloseableHttpClient httpClient;

    public HumifortisRiskEvaluator(KeycloakSession session) {
        // Use insecure SSL context if INSECURE_SSL=true, else default
        if ("true".equalsIgnoreCase(System.getenv("INSECURE_SSL"))) {
            try {
                TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
                };
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustAllCerts, new SecureRandom());
                this.httpClient = org.apache.http.impl.client.HttpClients.custom()
                        .setSSLContext(sslContext)
                        .build();
            } catch (Exception e) {
                throw new RuntimeException("Failed to create insecure SSL context", e);
            }
        } else {
            this.httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
        }
    }

    @Override
    public Set<EvaluationPhase> evaluationPhases() {
        return Set.of(EvaluationPhase.USER_KNOWN);
    }

    @Override
    public boolean allowRetries() {
        return false;
    }

    @Override
    public Risk evaluate(@Nonnull RealmModel realm, @Nullable UserModel knownUser) {

        if (knownUser == null) {
            logger.warnf("[HumifortisRiskEvaluator] User is null, fail open.");
            return lowestRisk(FAIL_OPEN_REASON);
        }

        String apiUrl = getEnvOrDefault(ENV_API_URL, DEFAULT_API_URL);
        String apiKey = System.getenv(ENV_API_KEY);
        int timeoutMs = parseTimeout(System.getenv(ENV_TIMEOUT_MS));
        boolean realmAsTenant = Boolean.parseBoolean(getEnvOrDefault(ENV_REALM_AS_TENANT, "true"));

        String userId = knownUser.getId() != null ? knownUser.getId() : knownUser.getUsername();
        // Always use the canonical entity_id format: user:keycloak:<realmid>:<user_id>
        String entityId = String.format("user:keycloak:%s:%s", realm.getName(), userId);


        if (apiKey == null || apiKey.isBlank()) {
            logger.warnf("[HumifortisRiskEvaluator] API key missing for entity_id=%s, fail open.", entityId);
            return lowestRisk(FAIL_OPEN_REASON);
        }


        if (!apiUrl.toLowerCase(Locale.ROOT).startsWith("https://")) {
            logger.warnf("[HumifortisRiskEvaluator] Non-HTTPS API URL for entity_id=%s, fail open.", entityId);
            return lowestRisk(FAIL_OPEN_REASON);
        }

        try {
            logger.infof("[HumifortisRiskEvaluator] Preparing to call Humifortis API: url=%s, entity_id=%s", apiUrl, entityId);
            String encodedEntityId = URLEncoder.encode(entityId, StandardCharsets.UTF_8);
            String requestUrl = apiUrl + "/decision/" + encodedEntityId;

            var request = new HttpGet(new URIBuilder(requestUrl).build());
            request.setHeader("Accept", "application/json");
            request.setHeader("X-API-Key", apiKey);
            request.setConfig(org.apache.http.client.config.RequestConfig.custom()
                    .setConnectTimeout(timeoutMs)
                    .setConnectionRequestTimeout(timeoutMs)
                    .setSocketTimeout(timeoutMs)
                    .build());

            logger.infof("[HumifortisRiskEvaluator] Sending request to: %s", requestUrl);
            try (var response = httpClient.execute(request)) {
                int status = response.getStatusLine().getStatusCode();
                logger.infof("[HumifortisRiskEvaluator] Received HTTP status: %d", status);
                if (status < 200 || status >= 300 || response.getEntity() == null) {
                    logger.warnf("[HumifortisRiskEvaluator] HTTP error for entity_id=%s: HTTP %d", entityId, status);
                    EntityUtils.consumeQuietly(response.getEntity());
                    return lowestRisk(FAIL_OPEN_REASON);
                }

                String body = EntityUtils.toString(response.getEntity());
                logger.infof("[HumifortisRiskEvaluator] API response body: %s", body);
                var decision = JsonSerialization.readValue(body, HumifortisDecisionResponse.class);
                String riskLevel = decision.risk_level != null ? decision.risk_level : "MINIMAL";
                String reason = decision.reason != null && !decision.reason.isBlank()
                        ? decision.reason
                        : "Humifortis decision received";

                Risk risk = mapRiskLevelToRisk(riskLevel, reason);
                logger.infof("[HumifortisRiskEvaluator] Final risk: %s, reason: %s", riskLevel, reason);
                return risk;
            }
        } catch (Exception e) {
            logger.warnf("[HumifortisRiskEvaluator] Exception for entity_id=%s: %s", entityId, e.getMessage());
            return lowestRisk(FAIL_OPEN_REASON);
        }
    }

    private static Risk mapRiskLevelToRisk(String riskLevel, String reason) {
        return switch (riskLevel.toUpperCase(Locale.ROOT)) {
            case "MINIMAL" -> Risk.of(Risk.Score.NONE, reason);
            case "LOW" -> Risk.of(Risk.Score.VERY_SMALL, reason);
            case "MEDIUM" -> Risk.of(Risk.Score.MEDIUM, reason);
            case "HIGH" -> Risk.of(Risk.Score.HIGH, reason);
            case "CRITICAL" -> Risk.of(Risk.Score.EXTREME, reason);
            default -> Risk.of(Risk.Score.NONE, reason);
        };
    }

    private static Risk lowestRisk(String reason) {
        return Risk.of(Risk.Score.NONE, reason);
    }

    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static int parseTimeout(String timeoutRaw) {
        if (timeoutRaw == null || timeoutRaw.isBlank()) {
            return DEFAULT_TIMEOUT_MS;
        }
        try {
            return Integer.parseInt(timeoutRaw);
        } catch (NumberFormatException e) {
            return DEFAULT_TIMEOUT_MS;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class HumifortisDecisionResponse {
        public String entity_id;
        public String action;
        public Double risk_score;
        public String risk_level;
        public String reason;
    }
}