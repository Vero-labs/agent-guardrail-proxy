// allow anything by default if risk is low
permit(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.risk < 50 &&
    context.confidence > 70
};

// forbid high risk prompts
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.risk > 80
};

// forbid sensitive data
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.sensitive == true
};

// forbid specific topics
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.topic == "Cryptocurrency"
};
