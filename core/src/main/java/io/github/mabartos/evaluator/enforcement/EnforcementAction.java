package io.github.mabartos.evaluator.enforcement;

/**
 * Represents a concrete enforcement action to be taken based on a Humifortis risk decision.
 * <p>
 * Enforcement actions are ordered by severity (lowest ordinal = least restrictive).
 * Each action carries a user-facing message key and an optional next-step hint.
 */
public enum EnforcementAction {

	/**
	 * Allow the authentication flow to continue without any challenge.
	 */
	ALLOW("enforcement.action.allow", null),

	/**
	 * Require the user to complete a reCAPTCHA challenge before proceeding.
	 */
	REQUIRE_RECAPTCHA("enforcement.action.recaptcha", "enforcement.hint.recaptcha"),

	/**
	 * Step up to multi-factor authentication (TOTP / OTP app).
	 */
	REQUIRE_MFA("enforcement.action.mfa", "enforcement.hint.mfa"),

	/**
	 * Send a one-time code to the user's registered email address and challenge them.
	 */
	REQUIRE_EMAIL_OTP("enforcement.action.email_otp", "enforcement.hint.email_otp"),

	/**
	 * Block the authentication attempt entirely and require administrator review.
	 */
	DENY("enforcement.action.deny", "enforcement.hint.deny");

	/** i18n message key describing what happened (shown on the login page). */
	private final String messageKey;

	/** i18n message key describing what the user should do next, or {@code null} for no hint. */
	private final String hintKey;

	EnforcementAction(String messageKey, String hintKey) {
		this.messageKey = messageKey;
		this.hintKey = hintKey;
	}

	public String getMessageKey() {
		return messageKey;
	}

	public String getHintKey() {
		return hintKey;
	}
}