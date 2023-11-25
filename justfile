# Helpers for testing JAWS

test:
    @echo "Running tests..."
    cargo hack test --feature-powerset --group-features ecdsa,p256,p384,p521

check:
    @echo "Checking..."
    cargo hack check --feature-powerset --group-features ecdsa,p256,p384,p521

doc:
    @echo "Building docs..."
    cargo doc --all-features
