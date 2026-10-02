package cryptox

import "testing"

func TestReservedInternalVariableNames(t *testing.T) {
	v := readVectors(t)
	for _, name := range []string{"__HARMONIA_STATE", "__harmonia_state", "__HaRmOnIa_STATE"} {
		m := v.Mutation.Mutation
		m.Name = name
		if _, err := m.SigningBytes(); err == nil {
			t.Fatalf("accepted internal mutation name %q", name)
		}
		c := ValueContext{m.AccountID, m.AccountGeneration, m.EnvironmentID, m.KeyVersion, name}
		if _, err := c.AssociatedData(); err == nil {
			t.Fatalf("accepted internal value name %q", name)
		}
	}
}
