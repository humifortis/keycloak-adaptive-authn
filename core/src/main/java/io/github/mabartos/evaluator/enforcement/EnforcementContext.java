package io.github.mabartos.evaluator.enforcement;

import io.github.mabartos.spi.level.Risk;

/**
 * Immutable value object that carries the complete enforcement context produced by
 * {@link EnforcementExecutor} for a single authentication attempt.
 */
public final class EnforcementContext {

    private final EnforcementAction action;
    private final Risk risk;
    /** i18n message key to display on the login page. */
    private final String userMessageKey;
    /** i18n next-step hint key (may be {@code null} for ALLOW). */
    private final String userHintKey;

    private EnforcementContext(EnforcementAction action, Risk risk,
                               String userMessageKey, String userHintKey) {
        this.action = action;
        this.risk = risk;
        this.userMessageKey = userMessageKey;
        this.userHintKey = userHintKey;
    }

    public static EnforcementContext of(EnforcementAction action, Risk risk) {
        return new EnforcementContext(action, risk, action.getMessageKey(), action.getHintKey());
    }

    public EnforcementAction getAction() { return action; }
    public Risk getRisk() { return risk; }
    public String getUserMessageKey() { return userMessageKey; }
    public String getUserHintKey() { return userHintKey; }

    public boolean isBlocking() {
        return action == EnforcementAction.DENY;
    }

    public boolean requiresChallenge() {
        return action == EnforcementAction.REQUIRE_RECAPTCHA
                || action == EnforcementAction.REQUIRE_MFA
                || action == EnforcementAction.REQUIRE_EMAIL_OTP;
    }

    @Override
    public String toString() {
        return "EnforcementContext{action=" + action + ", score=" + risk.getScore() + "}";
    }
}
