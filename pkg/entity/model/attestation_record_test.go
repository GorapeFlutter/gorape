package model

import "testing"

func TestResolveAssuranceUsesVerifiedEvidenceOnly(t *testing.T) {
	tests := []struct {
		name     string
		evidence AssuranceEvidence
		want     string
	}{
		{
			name: "unverified is rejected",
			evidence: AssuranceEvidence{
				Verified: false, HardwareProtected: true,
			},
			want: AssuranceLevelRejected,
		},
		{
			name: "fmt none BE=false is device bound, not hardware",
			evidence: AssuranceEvidence{
				Verified: true, SecurityLevel: "none",
			},
			want: AssuranceLevelDeviceBoundUnattested,
		},
		{
			name: "packed attestation alone does not prove hardware",
			evidence: AssuranceEvidence{
				Verified: true, SecurityLevel: "packed_attestation",
			},
			want: AssuranceLevelDeviceBoundUnattested,
		},
		{
			name: "verified hardware and BE=false is hardware attested",
			evidence: AssuranceEvidence{
				Verified: true, SecurityLevel: "android_key_attested", HardwareProtected: true,
			},
			want: AssuranceLevelHardwareAttested,
		},
		{
			name: "synchronizable credential is standard even with hardware attestation",
			evidence: AssuranceEvidence{
				Verified: true, SecurityLevel: "android_key_attested",
				HardwareProtected: true, BackupEligible: true,
			},
			want: AssuranceLevelStandardPasskey,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ResolveAssurance(test.evidence); got != test.want {
				t.Fatalf("ResolveAssurance() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLegacySecurityLevelMappingDoesNotPromotePackedOrMDS(t *testing.T) {
	for _, level := range []string{"packed_attestation", "fido_mds_verified", "self_attested", "none"} {
		if SecurityLevelProvesHardware(level) {
			t.Fatalf("security level %q must not prove hardware protection", level)
		}
	}
	for _, level := range []string{
		"strongbox", "trusted_environment", "tpm_attested",
		"android_key_attested", "apple_anonymous_attestation", "fido_u2f_attestation",
	} {
		if !SecurityLevelProvesHardware(level) {
			t.Fatalf("security level %q must prove hardware protection", level)
		}
	}
}

func TestEffectiveAssuranceDowngradesPersistedHardwareForSyncedCredential(t *testing.T) {
	record := Attestation{
		AssuranceLevel:     AssuranceLevelHardwareAttested,
		HardwareProtected:  true,
		BackupEligible:     false,
		VerificationStatus: "verified",
	}
	if got := record.EffectiveAssuranceLevel(false); got != AssuranceLevelHardwareAttested {
		t.Fatalf("BE=false level = %q, want hardware_attested", got)
	}
	if got := record.EffectiveAssuranceLevel(true); got != AssuranceLevelStandardPasskey {
		t.Fatalf("BE=true level = %q, want standard_passkey", got)
	}
	record.BackupEligible = true
	if got := record.EffectiveAssuranceLevel(false); got != AssuranceLevelStandardPasskey {
		t.Fatalf("stored BE=true level = %q, want standard_passkey", got)
	}
}
