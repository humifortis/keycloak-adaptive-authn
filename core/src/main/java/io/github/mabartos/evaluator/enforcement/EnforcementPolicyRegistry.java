package io.github.mabartos.evaluator.enforcement;

import io.github.mabartos.spi.level.Risk;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Discovers all registered {@link EnforcementPolicy} implementations via {@link ServiceLoader},
 * sorts them by priority, and delegates enforcement decisions to the first applicable policy.
 * <p>
 * The {@link DefaultEnforcementPolicy} is always added as the last-resort fallback so that
 * the registry never returns {@code null}.
 */
public final class EnforcementPolicyRegistry {

    private static final Logger logger = Logger.getLogger(EnforcementPolicyRegistry.class);

    private static final EnforcementPolicyRegistry INSTANCE = new EnforcementPolicyRegistry();

    private final List<EnforcementPolicy> policies;

    private EnforcementPolicyRegistry() {
        List<EnforcementPolicy> discovered = new ArrayList<>();

        // Discover any custom implementations on the classpath
        ServiceLoader<EnforcementPolicy> loader =
                ServiceLoader.load(EnforcementPolicy.class, Thread.currentThread().getContextClassLoader());
        for (EnforcementPolicy policy : loader) {
            discovered.add(policy);
            logger.infof("[EnforcementPolicyRegistry] Discovered policy: %s (priority=%d)",
                    policy.getClass().getName(), policy.priority());
        }

        // Always include the built-in default as the final fallback
        discovered.add(new DefaultEnforcementPolicy());

        discovered.sort(Comparator.comparingInt(EnforcementPolicy::priority));
        this.policies = List.copyOf(discovered);
        logger.infof("[EnforcementPolicyRegistry] Loaded %d enforcement polic(ies).", policies.size());
    }

    public static EnforcementPolicyRegistry getInstance() {
        return INSTANCE;
    }

    /**
     * Determine the enforcement action for the given risk context.
     * Iterates policies in priority order and returns the first non-null decision.
     */
    public EnforcementAction resolve(Risk risk, RealmModel realm, UserModel user) {
        for (EnforcementPolicy policy : policies) {
            try {
                EnforcementAction action = policy.decide(risk, realm, user);
                if (action != null) {
                    logger.infof("[EnforcementPolicyRegistry] Policy %s resolved action=%s for score=%s",
                            policy.getClass().getSimpleName(), action, risk.getScore());
                    return action;
                }
            } catch (Exception e) {
                logger.warnf("[EnforcementPolicyRegistry] Policy %s threw exception, skipping: %s",
                        policy.getClass().getSimpleName(), e.getMessage());
            }
        }
        // Should never reach here because DefaultEnforcementPolicy always returns a value
        logger.warn("[EnforcementPolicyRegistry] No policy produced a decision, falling back to DENY.");
        return EnforcementAction.DENY;
    }
}
