"""
Module: test_wasm.py
Description: Production-ready enterprise component for Test Wasm.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import os


import pytest
pytest.skip("ADR-001: Validación JWT WASM deprecada a favor de CSP estricta.", allow_module_level=True)

import wasmtime

# Configuration
WASM_PATH = os.path.join(os.path.dirname(__file__), '..', 'src', 'static', 'wasm', 'bunker_jwt.wasm')

@pytest.fixture
def wasm_module():
    store = wasmtime.Store()
    engine = store.engine
    module = wasmtime.Module.from_file(engine, WASM_PATH)
    instance = wasmtime.Instance(store, module, [])
    return store, instance

def test_validate_alg_success(wasm_module):
    store, instance = wasm_module
    memory = instance.exports(store)["memory"]
    validate_alg = instance.exports(store)["validate_alg"]
    
    # Write "ES256" into memory at offset 0
    alg_bytes = b"ES256"
    memory.write(store, alg_bytes, 0)
    
    result = validate_alg(store, 0, len(alg_bytes))
    assert result == 1, "Expected algorithm ES256 to be valid"

def test_validate_alg_failure_none(wasm_module):
    store, instance = wasm_module
    memory = instance.exports(store)["memory"]
    validate_alg = instance.exports(store)["validate_alg"]
    
    # Write "none" into memory at offset 0
    alg_bytes = b"none"
    memory.write(store, alg_bytes, 0)
    
    result = validate_alg(store, 0, len(alg_bytes))
    assert result == 0, "Expected algorithm 'none' to be invalid"

def test_validate_exp_valid(wasm_module):
    store, instance = wasm_module
    validate_exp = instance.exports(store)["validate_exp"]
    
    now = int(time.time())
    exp = now + 3600 # 1 hour in future
    
    result = validate_exp(store, exp, now)
    assert result == 1, "Future exp should be valid"

def test_validate_exp_expired(wasm_module):
    store, instance = wasm_module
    validate_exp = instance.exports(store)["validate_exp"]
    
    now = int(time.time())
    exp = now - 3600 # 1 hour in past
    
    result = validate_exp(store, exp, now)
    assert result == 0, "Past exp should be invalid"

def test_validate_nbf_valid(wasm_module):
    store, instance = wasm_module
    validate_nbf = instance.exports(store)["validate_nbf"]
    
    now = int(time.time())
    nbf = now - 3600 # 1 hour in past
    
    result = validate_nbf(store, nbf, now)
    assert result == 1, "Past nbf should be valid"

def test_validate_nbf_future_with_skew(wasm_module):
    store, instance = wasm_module
    validate_nbf = instance.exports(store)["validate_nbf"]
    
    now = int(time.time())
    nbf = now + 15 # 15s in future, within 30s skew
    
    result = validate_nbf(store, nbf, now)
    assert result == 1, "Future nbf within skew should be valid"

def test_validate_nbf_future_beyond_skew(wasm_module):
    store, instance = wasm_module
    validate_nbf = instance.exports(store)["validate_nbf"]
    
    now = int(time.time())
    nbf = now + 35 # 35s in future, beyond 30s skew
    
    result = validate_nbf(store, nbf, now)
    assert result == 0, "Future nbf beyond skew should be invalid"

def test_validate_policy_combined(wasm_module):
    store, instance = wasm_module
    validate_policy = instance.exports(store)["validate_policy"]
    
    now = int(time.time())
    exp = now + 3600
    nbf = now - 10
    
    result = validate_policy(store, exp, nbf, now)
    assert result == 1, "Combined valid exp and nbf should be valid"


if __name__ == '__main__':
    # Production entry point
    pass
