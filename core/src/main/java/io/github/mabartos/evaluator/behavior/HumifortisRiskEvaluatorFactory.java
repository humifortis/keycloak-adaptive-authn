package io.github.mabartos.evaluator.behavior;

import io.github.mabartos.spi.evaluator.RiskEvaluator;
import io.github.mabartos.spi.evaluator.RiskEvaluatorFactory;
import org.keycloak.models.KeycloakSession;

public class HumifortisRiskEvaluatorFactory implements RiskEvaluatorFactory {
    public static final String PROVIDER_ID = "humifortis";
    public static final String NAME = "Humifortis Decision Risk Evaluator";

    @Override
    public RiskEvaluator create(KeycloakSession session) {
        return new HumifortisRiskEvaluator(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Class<? extends RiskEvaluator> evaluatorClass() {
        return HumifortisRiskEvaluator.class;
    }
}