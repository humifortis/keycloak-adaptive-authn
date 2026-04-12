package io.github.mabartos.evaluator.enforcement;

import io.github.mabartos.spi.level.Risk;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.Response;

/**
 * Executes a resolved {@link EnforcementContext} against the Keycloak
 * {@link AuthenticationFlowContext}.
 *
 * <h3>Supported actions</h3>
 * <ul>
 *   <li>{@link EnforcementAction#ALLOW}            — calls {@code context.success()}</li>
 *   <li>{@link EnforcementAction#REQUIRE_RECAPTCHA} — adds a reCAPTCHA required-action and
 *       returns an HTTP 401 challenge with a localised user message</li>
 *   <li>{@link EnforcementAction#REQUIRE_MFA}       — marks the user for OTP setup/verification
 *       via a required-action, then continues the flow so Keycloak's built-in OTP step fires</li>
 *   <li>{@link EnforcementAction#REQUIRE_EMAIL_OTP} — sends an email OTP via Keycloak's
 *       built-in email action and presents a verify-email challenge page</li>
 *   <li>{@link EnforcementAction#DENY}              — fails the flow with ACCESS_DENIED and
 *       a descriptive user error message</li>
 * </ul>
 *
 * <h3>Feedback event contract</h3>
 * <p>
 * {@link io.github.mabartos.evaluator.behavior.HumifortisRiskAuthenticator} is responsible
 * for stamping the primary risk details (HUMIFORTIS_RISK_ACTION, SCORE, LEVEL, REASON) onto
 * the Keycloak event <em>before</em> the flow ends.  This executor adds the two remaining
 * pieces that are only known at execution time:
 * <ul>
 *   <li>{@code HUMIFORTIS_RISK_BLOCKED=true} — set only on DENY, so the listener can
 *       distinguish a block from other LOGIN_ERROR events.</li>
 *   <li>{@code userId} — populated here so feedback events on failed logins carry the
 *       user identity even when Keycloak's event user field is null.</li>
 * </ul>
 * <p>
 * This executor deliberately does <strong>NOT</strong> call
 * {@code context.getEvent().type(...)} or {@code context.getEvent().error(...)}.
 * Those calls replace the event type/error that Keycloak itself sets when the flow
 * ends (LOGIN vs LOGIN_ERROR), which would corrupt the event and prevent the
 * listener from ever seeing it.
 */
public final class EnforcementExecutor {

    private static final Logger logger = Logger.getLogger(EnforcementExecutor.class);

    // Keycloak built-in required-action aliases
    private static final String RA_CONFIGURE_TOTP = "CONFIGURE_TOTP";
    private static final String RA_VERIFY_EMAIL    = "VERIFY_EMAIL";

    // ── Detail keys written into context.getEvent() ─────────────────────────
    // Primary keys (LEVEL, REASON, ACTION, SCORE) are written by
    // HumifortisRiskAuthenticator.stampEventDetails() before this executor runs.
    // This class adds the execution-time keys below.

    /** Set to "true" only when the decision is DENY. Read by HumifortisEventListener
     *  to distinguish auth_decision_block from auth_decision_evaluated. */
    public static final String NOTE_RISK_BLOCKED = "HUMIFORTIS_RISK_BLOCKED";

    // Auth-session note keys — survive across the full flow and are readable by
    // downstream authenticators.  Kept for compatibility with any other components
    // that read auth-session notes rather than event details.
    public static final String NOTE_RISK_LEVEL   = "HUMIFORTIS_RISK_LEVEL";
    public static final String NOTE_RISK_REASON  = "HUMIFORTIS_RISK_REASON";
    public static final String NOTE_RISK_ACTION  = "HUMIFORTIS_RISK_ACTION";
    public static final String NOTE_RISK_SCORE   = "HUMIFORTIS_RISK_SCORE";

    private EnforcementExecutor() {}

    /**
     * Apply the enforcement decision to the Keycloak authentication flow.
     *
     * @param context the active authentication flow context
     * @param enfCtx  the resolved enforcement context
     */
    public static void execute(AuthenticationFlowContext context, EnforcementContext enfCtx) {
        Risk risk             = enfCtx.getRisk();
        EnforcementAction action = enfCtx.getAction();

        logger.infof("[EnforcementExecutor] Executing action=%s score=%s reason=%s",
                action, risk.getScore(), risk.getReason().orElse(""));

        // ── 1. Persist auth-session notes (readable by downstream steps) ─────
        storeAuthSessionNotes(context, risk, action);

        // ── 2. Stamp execution-time event details ────────────────────────────
        //    Only add details that are known here; do NOT touch .type()/.error()
        //    — Keycloak sets those when the flow ends.
        stampExecutionDetails(context, action);

        // ── 3. Execute the enforcement action ────────────────────────────────
        switch (action) {
            case ALLOW             -> handleAllow(context);
            case REQUIRE_RECAPTCHA -> handleRecaptcha(context, enfCtx);
            case REQUIRE_MFA       -> handleMfa(context, enfCtx);
            case REQUIRE_EMAIL_OTP -> handleEmailOtp(context, enfCtx);
            case DENY              -> handleDeny(context, enfCtx);
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Stores risk data in auth-session notes so downstream authenticators can
     * read them independently of the Keycloak event lifecycle.
     * Does NOT touch context.getEvent() — that is handled separately.
     */
    private static void storeAuthSessionNotes(
            AuthenticationFlowContext context, Risk risk, EnforcementAction action) {

        try {
            var session = context.getAuthenticationSession();
            String reason = risk.getReason().orElse("");
            session.setAuthNote(NOTE_RISK_LEVEL,  risk.getScore().name());
            session.setAuthNote(NOTE_RISK_REASON, reason);
            session.setAuthNote(NOTE_RISK_ACTION, action.name());
            session.setAuthNote(NOTE_RISK_SCORE,  String.valueOf(risk.getScore().ordinal()));

            if (action == EnforcementAction.DENY) {
                session.setAuthNote(NOTE_RISK_BLOCKED, "true");
            }
        } catch (Exception e) {
            logger.warnf("[EnforcementExecutor] Failed to store auth-session notes: %s",
                    e.getMessage());
        }
    }

    /**
     * Stamps execution-time details onto the Keycloak event so that
     * HumifortisEventListener can read them from the resulting LOGIN /
     * LOGIN_ERROR event.
     *
     * <p><strong>Critical:</strong> this method only calls {@code event.detail()}.
     * It never calls {@code event.type()} or {@code event.error()} — those calls
     * would overwrite the event type/error that Keycloak sets at flow completion,
     * which would prevent the listener from receiving a well-formed event.</p>
     *
     * <p>The primary risk details (ACTION, SCORE, LEVEL, REASON) are already
     * on the event from HumifortisRiskAuthenticator.  Here we add:</p>
     * <ul>
     *   <li>{@code HUMIFORTIS_RISK_BLOCKED} — only "true" on DENY, distinguishes
     *       block events from other LOGIN_ERROR events in the listener.</li>
     *   <li>{@code userId} — ensures deny/challenge events carry the user id even
     *       if Keycloak hasn't set it on the event yet at this point in the flow.</li>
     * </ul>
     */
    private static void stampExecutionDetails(
            AuthenticationFlowContext context, EnforcementAction action) {

        try {
            var event = context.getEvent();
            if (event == null) {
                logger.warnf("[EnforcementExecutor] context.getEvent() is null — " +
                        "cannot stamp execution details.");
                return;
            }

            // Tag blocked events so the listener maps them to auth_decision_block
            if (action == EnforcementAction.DENY) {
                event.detail(NOTE_RISK_BLOCKED, "true");
                logger.infof("[EnforcementExecutor] Stamped HUMIFORTIS_RISK_BLOCKED=true");
            }

            // Always ensure userId is on the event for reliable entity resolution
            UserModel user = context.getUser();
            if (user != null && user.getId() != null) {
                event.detail("userId", user.getId());
            }

        } catch (Exception e) {
            logger.warnf("[EnforcementExecutor] Failed to stamp execution details: %s",
                    e.getMessage());
        }
    }

    private static void handleAllow(AuthenticationFlowContext context) {
        logger.info("[EnforcementExecutor] ALLOW – authentication success.");
        context.success();
    }

    private static void handleRecaptcha(AuthenticationFlowContext context, EnforcementContext enfCtx) {
        logger.info("[EnforcementExecutor] REQUIRE_RECAPTCHA – presenting reCAPTCHA challenge.");
        context.getAuthenticationSession().addRequiredAction("humifortis-recaptcha-challenge");
        Response challenge = context.form()
                .setError(enfCtx.getUserMessageKey())
                .createForm("humifortis-recaptcha.ftl");
        context.challenge(challenge);
    }

    private static void handleMfa(AuthenticationFlowContext context, EnforcementContext enfCtx) {
        logger.info("[EnforcementExecutor] REQUIRE_MFA – stepping up to OTP.");
        UserModel user = context.getUser();
        if (user != null && !user.credentialManager().isConfiguredFor(
                org.keycloak.models.credential.OTPCredentialModel.TYPE)) {
            user.addRequiredAction(RA_CONFIGURE_TOTP);
        }
        context.getAuthenticationSession().addRequiredAction(RA_CONFIGURE_TOTP);
        Response challenge = context.form()
                .setInfo(enfCtx.getUserMessageKey())
                .createForm("humifortis-mfa-required.ftl");
        context.challenge(challenge);
    }

    private static void handleEmailOtp(AuthenticationFlowContext context, EnforcementContext enfCtx) {
        logger.info("[EnforcementExecutor] REQUIRE_EMAIL_OTP – sending email OTP.");
        UserModel user = context.getUser();
        if (user != null) {
            user.addRequiredAction(RA_VERIFY_EMAIL);
            context.getAuthenticationSession().addRequiredAction(RA_VERIFY_EMAIL);
        }
        Response challenge = context.form()
                .setInfo(enfCtx.getUserMessageKey())
                .createForm("humifortis-email-otp.ftl");
        context.challenge(challenge);
    }

    private static void handleDeny(AuthenticationFlowContext context, EnforcementContext enfCtx) {
        logger.infof("[EnforcementExecutor] DENY – blocking authentication. reason=%s",
                enfCtx.getRisk().getReason().orElse(""));
        Response errorResponse = context.form()
                .setError(enfCtx.getUserMessageKey(),
                        enfCtx.getRisk().getReason().orElse(""))
                .createErrorPage(Response.Status.FORBIDDEN);
        context.failure(AuthenticationFlowError.ACCESS_DENIED, errorResponse);
    }
}