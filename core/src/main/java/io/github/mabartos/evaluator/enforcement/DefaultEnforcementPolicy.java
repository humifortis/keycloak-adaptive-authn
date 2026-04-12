package io.github.mabartos.evaluator.enforcement;

import io.github.mabartos.spi.level.Risk;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Built-in {@link EnforcementPolicy} that maps Humifortis {@link Risk.Score} values to
 * enforcement actions using a progressive, adaptive-authentication model:
 *
 * <pre>
 *  NONE / VERY_SMALL   → ALLOW
 *  SMALL               → REQUIRE_RECAPTCHA
 *  MEDIUM              → REQUIRE_MFA
 *  HIGH                → REQUIRE_EMAIL_OTP
 *  VERY_HIGH / EXTREME → DENY
 * </pre>
 *
 * Replace or extend this class by registering a higher-priority {@link EnforcementPolicy}
 * implementation in {@code META-INF/services/io.github.mabartos.evaluator.enforcement.EnforcementPolicy}.
 */
public class DefaultEnforcementPolicy implements EnforcementPolicy {

    @Override
    public EnforcementAction decide(Risk risk, RealmModel realm, UserModel user) {
        return switch (risk.getScore()) {
            case NONE, VERY_SMALL -> EnforcementAction.ALLOW;
            case SMALL            -> EnforcementAction.REQUIRE_RECAPTCHA;
            case MEDIUM           -> EnforcementAction.REQUIRE_MFA;
            case HIGH             -> EnforcementAction.REQUIRE_EMAIL_OTP;
            case VERY_HIGH, EXTREME -> EnforcementAction.DENY;
            default -> EnforcementAction.DENY;
        };
    }

    @Override
    public int priority() {
        // Lowest priority – acts as the final fallback
        return Integer.MAX_VALUE;
    }
}
