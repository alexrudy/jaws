# Helpers for testing JAWS

test:
    @echo "Running tests..."
    just hack test

check:
    @echo "Checking..."
    just hack check

hack cmd:
    cargo hack {{cmd}} --feature-powerset --group-features rsa,ecdsa,p256,p384,p521,pss,ed25519
    cargo hack  {{cmd}} --features spki,der,rand,fmt --each-feature --include-features rsa,p256,p384,p521,pss,ed25519
    cargo hack  {{cmd}} --each-feature --include-features rsa,p256,p384,p521,pss,ed25519

doc:
    @echo "Building docs..."
    cargo doc --all-features
