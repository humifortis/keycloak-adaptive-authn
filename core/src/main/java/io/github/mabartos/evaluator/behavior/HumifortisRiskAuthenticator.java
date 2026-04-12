package io.github.mabartos.evaluator.behavior;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import io.github.mabartos.spi.level.Risk;
import io.github.mabartos.evaluator.enforcement.EnforcementPolicyRegistry;
import io.github.mabartos.evaluator.enforcement.EnforcementContext;
import io.github.mabartos.evaluator.enforcement.EnforcementExecutor;

/**
 * Risk-based authenticator that:
 *  1. Evaluates risk via HumifortisRiskEvaluator.
 *  2. Resolves an enforcement action (ALLOW / CHALLENGE_MFA / BLOCK).
 *  3. Fires a dedicated CUSTOM_REQUIRED_ACTION event immediately so that
 *     HumifortisEventListener receives the risk decision data reliably,
 *     independent of the flow's terminal LOGIN/LOGIN_ERROR event.
 *  4. Executes the enforcement action (allow / challenge / deny).
 *
 * WHY WE FIRE OUR OWN EVENT:
 *   context.getEvent().detail() targets the flow-context EventBuilder, which
 *   Keycloak discards when the flow ends — it never reaches the listener.
 *   Auth-session notes require the listener to locate the session by ID at
 *   event time, which is fragile. The simplest, most reliable solution is to
 *   construct a new EventBuilder and fire it ourselves right here, before
 *   handing off to EnforcementExecutor. Keycloak dispatches it immediately
 *   to all registered EventListenerProviders.
 *
 * EVENT CONTRACT (type = CUSTOM_REQUIRED_ACTION, error = "humifortis_risk_decision"):
 *   detail HUMIFORTIS_RISK_ACTION  – ALLOW | REQUIRE_MFA | DENY | …
 *   detail HUMIFORTIS_RISK_SCORE   – Risk.Score ordinal as string
 *   detail HUMIFORTIS_RISK_LEVEL   – MINIMAL | LOW | MEDIUM | HIGH | CRITICAL
 *   detail HUMIFORTIS_RISK_REASON  – human-readable reason
 *   detail HUMIFORTIS_RISK_BLOCKED – "true" only when action is DENY
 */
public class HumifortisRiskAuthenticator implements Authenticator {

    private static final Logger logger =
            Logger.getLogger(HumifortisRiskAuthenticator.class);

    // Detail keys — must match HumifortisEventListener constants exactly.
    public static final String DETAIL_RISK_ACTION  = "HUMIFORTIS_RISK_ACTION";
    public static final String DETAIL_RISK_SCORE   = "HUMIFORTIS_RISK_SCORE";
    public static final String DETAIL_RISK_LEVEL   = "HUMIFORTIS_RISK_LEVEL";
    public static final String DETAIL_RISK_REASON  = "HUMIFORTIS_RISK_REASON";
    public static final String DETAIL_RISK_BLOCKED = "HUMIFORTIS_RISK_BLOCKED";

    // Sentinel error string on the fired event so the listener can identify it.
    public static final String RISK_EVENT_ERROR = "humifortis_risk_decision";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.infof("[HumifortisRiskAuthenticator] Invoked for realm=%s user=%s",
                context.getRealm().getName(),
                context.getUser() != null ? context.getUser().getUsername() : "null");

        // ── Step 1: Evaluate risk ────────────────────────────────────────────
        HumifortisRiskEvaluator evaluator =
                new HumifortisRiskEvaluator(context.getSession());
        Risk risk = evaluator.evaluate(context.getRealm(), context.getUser());

        logger.infof("[HumifortisRiskAuthenticator] Risk result: score=%s reason=%s",
                risk.getScore(), risk.getReason().orElse(""));

        // ── Step 2: Resolve enforcement action ───────────────────────────────
        var action = EnforcementPolicyRegistry.getInstance()
                .resolve(risk, context.getRealm(), context.getUser());

        logger.infof("[HumifortisRiskAuthenticator] Enforcement action: %s", action);

        // ── Step 3: Fire a dedicated risk-decision event immediately ─────────
        // This event is dispatched right now to all EventListenerProviders,
        // bypassing the flow lifecycle entirely.
        fireRiskDecisionEvent(context, risk, action);

        // ── Step 4: Execute the enforcement action ───────────────────────────
        EnforcementContext enfCtx = EnforcementContext.of(action, risk);
        EnforcementExecutor.execute(context, enfCtx);
    }

    /**
     * Constructs and immediately fires a Keycloak event carrying the full risk
     * decision payload. The event uses type {@link EventType#CUSTOM_REQUIRED_ACTION}
     * with error string {@value #RISK_EVENT_ERROR} so the listener can
     * distinguish it from normal login events without scanning all LOGIN_ERROR
     * events.
     *
     * <p>EventBuilder.error() dispatches the event synchronously to every
     * registered EventListenerProvider — the listener receives it before
     * EnforcementExecutor runs.</p>
     */
    private void fireRiskDecisionEvent(
            AuthenticationFlowContext context,
            Risk risk,
            Object action) {

        try {
            String actionName = action != null ? action.toString() : "UNKNOWN";
            String scoreStr   = String.valueOf(risk.getScore().ordinal());
            String levelStr   = deriveRiskLevel(risk);
            String reasonStr  = risk.getReason().orElse("");
            boolean isBlock   = "DENY".equalsIgnoreCase(actionName);

            // Build a fresh event — do NOT reuse context.getEvent() because
            // that builder is owned by the flow and its state is unpredictable.
            EventBuilder event = context.getEvent()
                    .clone()
                    .event(EventType.CUSTOM_REQUIRED_ACTION)
                    .detail(DETAIL_RISK_ACTION,  actionName)
                    .detail(DETAIL_RISK_SCORE,   scoreStr)
                    .detail(DETAIL_RISK_LEVEL,   levelStr)
                    .detail(DETAIL_RISK_REASON,  reasonStr)
                    .detail(DETAIL_RISK_BLOCKED, String.valueOf(isBlock));

            // Attach user identity if available
            UserModel user = context.getUser();
            if (user != null) {
                event.user(user);
            }

            // .error() dispatches immediately to all listeners.
            // We use an error string rather than .success() so the event
            // carries a queryable discriminator without appearing as a
            // legitimate login error in Keycloak's own audit log.
            event.error(RISK_EVENT_ERROR);

            logger.infof("[HumifortisRiskAuthenticator] Risk decision event fired: " +
                            "action=%s score=%s level=%s blocked=%s",
                    actionName, scoreStr, levelStr, isBlock);

        } catch (Exception e) {
            // Never let event firing break the auth flow
            logger.warnf("[HumifortisRiskAuthenticator] " +
                    "Failed to fire risk decision event: %s", e.getMessage());
        }
    }

    private String deriveRiskLevel(Risk risk) {
        if (risk.getScore() == null) return "MINIMAL";
        return switch (risk.getScore()) {
            case NONE, INVALID, NEGATIVE_HIGH, NEGATIVE_LOW -> "MINIMAL";
            case VERY_SMALL, SMALL                          -> "LOW";
            case MEDIUM                                     -> "MEDIUM";
            case HIGH, VERY_HIGH                            -> "HIGH";
            case EXTREME                                    -> "CRITICAL";
        };
    }

    @Override public void action(AuthenticationFlowContext context) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(
            org.keycloak.models.KeycloakSession session,
            org.keycloak.models.RealmModel realm,
            UserModel user) { return true; }
    @Override public void setRequiredActions(
            org.keycloak.models.KeycloakSession session,
            org.keycloak.models.RealmModel realm,
            UserModel user) { }
    @Override public void close() { }
}