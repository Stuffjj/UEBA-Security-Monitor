# UEBA Security Monitoring System - Test Results

## 1. Detection Helper Tests

- Circular time difference: PASS
- Normal login hour calculation: PASS
- Failed login window detection: PASS
- Failed login window separation: PASS

Result: 4 tests passed.

## 2. Detection Integration Tests

- Unfamiliar IP login detection: PASS
- Unusual login time detection: PASS
- Multiple failed login detection: PASS

Result: 3 detection scenarios passed.

## 3. Risk Scoring Tests

| Test User | Expected Score | Risk Level | Result |
|---|---:|---|---|
| normal_user | 0 | LOW | PASS |
| medium_user | 15 | LOW | PASS |
| high_user | 60 | HIGH | PASS |
| critical_user | 90 | CRITICAL | PASS |

Result: 4 risk scoring tests passed.

## 4. Audit Functionality

- Database initialization: PASS
- Security incidents table verification: PASS
- Investigation fields verification: PASS
- Incident audit history: PASS
- Incident status update: PASS

## Conclusion

The tested UEBA detection, risk scoring, and audit workflows produced the expected results using simulated login data.

These tests demonstrate the project's current functionality. They do not establish production readiness or detection accuracy against real-world attacks.