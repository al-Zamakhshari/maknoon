// Package-level audit infrastructure.
// Loggers are in audit_loggers.go; the AuditEngine decorator is in audit_engine.go.
package crypto

// Compile-time assertion: AuditEngine must satisfy the full MaknoonEngine interface.
var _ MaknoonEngine = (*AuditEngine)(nil)
