package io.github.mabartos.evaluator.behavior;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.UserModel;

public class HumifortisRiskAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(HumifortisRiskAuthenticator.class);
        logger.infof("[HumifortisRiskAuthenticator] Invoked for realm=%s user=%s", context.getRealm().getName(), context.getUser() != null ? context.getUser().getUsername() : "null");

        HumifortisRiskEvaluator evaluator = new HumifortisRiskEvaluator(context.getSession());
        logger.info("[HumifortisRiskAuthenticator] Calling HumifortisRiskEvaluator.evaluate()...");
        var risk = evaluator.evaluate(context.getRealm(), context.getUser());
        logger.infof("[HumifortisRiskAuthenticator] Risk evaluation result: score=%s, reason=%s", risk.getScore(), risk.getReason());
        // Store risk level, reason, and derived action in auth session notes and event details
        context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_LEVEL", risk.getScore().name());
        context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_REASON", risk.getReason() != null ? risk.getReason().orElse("") : "");
        String action = risk.getScore().ordinal() < io.github.mabartos.spi.level.Risk.Score.MEDIUM.ordinal() ? "ALLOW" : "BLOCK";
        context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_ACTION", action);
        if (context.getEvent() != null) {
            context.getEvent().detail("HUMIFORTIS_RISK_LEVEL", risk.getScore().name());
            context.getEvent().detail("HUMIFORTIS_RISK_REASON", risk.getReason() != null ? risk.getReason().orElse("") : "");
            context.getEvent().detail("HUMIFORTIS_RISK_ACTION", action);
        }
        boolean allow = risk.getScore().ordinal() < io.github.mabartos.spi.level.Risk.Score.MEDIUM.ordinal();
        if (allow) {
            logger.info("[HumifortisRiskAuthenticator] Risk below MEDIUM, authentication success.");
            context.success();
        } else {
            logger.info("[HumifortisRiskAuthenticator] Risk MEDIUM or above, authentication failure.");
            // Set a marker for event listener correlation
            context.getAuthenticationSession().setAuthNote("HUMIFORTIS_RISK_BLOCKED", "true");
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    }

    @Override public void action(AuthenticationFlowContext context) { }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) { }
    @Override public void close() { }
}
