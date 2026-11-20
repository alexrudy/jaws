# Helpers for testing JAWS

test:
    @echo "Running tests..."
    cargo hack test --feature-powerset --group-features ecdsa,p256,p384,p521,pss,ed25519
    cargo hack test --features spki,der,rand,fmt --each-feature --include-features rsa,p256,p384,p521,pss,ed25519
    cargo hack test --each-feature --include-features rsa,p256,p384,p521,pss,ed25519

check:
    @echo "Checking..."
    cargo hack check --feature-powerset --group-features ecdsa,p256,p384,p521,pss,ed25519

doc:
    @echo "Building docs..."
    cargo doc --all-features
