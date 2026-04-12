package io.github.mabartos.evaluator.enforcement;

import io.github.mabartos.spi.level.Risk;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * SPI for mapping a Humifortis {@link Risk} assessment to a concrete {@link EnforcementAction}.
 * <p>
 * Implementations are discovered via Java {@link java.util.ServiceLoader} and registered as
 * Keycloak providers.  The first implementation that returns a non-{@code null} action wins;
 * the {@link DefaultEnforcementPolicy} serves as a safe built-in fallback.
 * <p>
 * Implement this interface to add custom enforcement strategies such as:
 * <ul>
 *   <li>Tenant-specific risk thresholds</li>
 *   <li>Context-aware policies (IP allowlisting, device fingerprint, etc.)</li>
 *   <li>Progressive enforcement (escalate on repeated failures)</li>
 * </ul>
 */
public interface EnforcementPolicy {

    /**
     * Evaluate the risk and decide which enforcement action to apply.
     *
     * @param risk  the risk assessment returned by the Humifortis evaluator; never {@code null}
     * @param realm the Keycloak realm context; never {@code null}
     * @param user  the authenticated user; may be {@code null} if the user is unknown
     * @return the enforcement action to apply; must not be {@code null}
     */
    EnforcementAction decide(Risk risk, RealmModel realm, UserModel user);

    /**
     * Priority of this policy relative to others.
     * Lower value = higher priority (evaluated first).
     * The {@link DefaultEnforcementPolicy} uses {@link Integer#MAX_VALUE} so it is always last.
     */
    default int priority() {
        return Integer.MAX_VALUE;
    }
}
