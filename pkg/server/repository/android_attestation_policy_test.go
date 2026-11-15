package repository

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"testing"
)

func TestAndroidAttestationPolicyRequiresExactPackageDigestConfiguration(t *testing.T) {
	digest := sha256.Sum256([]byte("expected signing certificate"))
	if (AndroidAttestationPolicy{}).Configured() {
		t.Fatal("empty Android app identity policy must remain unconfigured")
	}
	valid := AndroidAttestationPolicy{Applications: map[string][]string{
		"com.gorapeflutter.gf_app": {hex.EncodeToString(digest[:])},
	}}
	if !valid.Configured() {
		t.Fatal("well-formed package/signing digest policy should be configured")
	}
	invalid := AndroidAttestationPolicy{Applications: map[string][]string{
		"com.gorapeflutter.gf_app": {"not-a-sha256-digest"},
	}}
	if invalid.Configured() {
		t.Fatal("malformed signing digest policy must remain unconfigured")
	}
}

func TestAndroidAuthorizationPolicyRequiresHardwareKeyAndTrustedBoot(t *testing.T) {
	digest := sha256.Sum256([]byte("test signing certificate"))
	policy := AndroidAttestationPolicy{
		Applications: map[string][]string{
			"com.gorapeflutter.gf_app": {hex.EncodeToString(digest[:])},
		},
		MinimumOSVersion:        140000,
		MinimumOSPatchLevel:     202601,
		MinimumVendorPatchLevel: 20260101,
		MinimumBootPatchLevel:   20260101,
	}

	valid := androidPolicyDescription(t, true, 140100, 202601, 20260102, 20260103, digest[:])
	if err := (&AndroidVerifier{policy: policy}).verifyAuthorizationPolicy(valid); err != nil {
		t.Fatalf("valid Android attestation policy rejected: %v", err)
	}
	wrongDigest := sha256.Sum256([]byte("different signing certificate"))

	for _, test := range []struct {
		name string
		keyDescription
	}{
		{name: "device unlocked", keyDescription: androidPolicyDescription(t, false, 140100, 202601, 20260102, 20260103, digest[:])},
		{name: "old os patch", keyDescription: androidPolicyDescription(t, true, 140100, 202512, 20260102, 20260103, digest[:])},
		{name: "wrong app digest", keyDescription: androidPolicyDescription(t, true, 140100, 202601, 20260102, 20260103, wrongDigest[:])},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := (&AndroidVerifier{policy: policy}).verifyAuthorizationPolicy(test.keyDescription); err == nil {
				t.Fatal("expected Android attestation policy failure")
			}
		})
	}
}

func TestAndroidAuthorizationPolicyRejectsSoftwareEnforcedSigningParameters(t *testing.T) {
	digest := sha256.Sum256([]byte("test signing certificate"))
	policy := AndroidAttestationPolicy{Applications: map[string][]string{"com.gorapeflutter.gf_app": {hex.EncodeToString(digest[:])}}}
	kd := androidPolicyDescription(t, true, 140000, 202601, 20260101, 20260101, digest[:])
	software, err := parseAndroidAuthorizationList(kd.SoftwareEnforced)
	if err != nil {
		t.Fatal(err)
	}
	tee, err := parseAndroidAuthorizationList(kd.TEEEnforced)
	if err != nil {
		t.Fatal(err)
	}
	algorithm := tee[androidTagAlgorithm]
	delete(tee, androidTagAlgorithm)
	software[androidTagAlgorithm] = algorithm
	kd.SoftwareEnforced = marshalAndroidAuthorizationList(t, software)
	kd.TEEEnforced = marshalAndroidAuthorizationList(t, tee)
	if err := (&AndroidVerifier{policy: policy}).verifyAuthorizationPolicy(kd); err == nil {
		t.Fatal("software-enforced algorithm attribute must be rejected")
	}
}

func androidPolicyDescription(t *testing.T, locked bool, osVersion, osPatch, vendorPatch, bootPatch int, digest []byte) keyDescription {
	t.Helper()
	rootDER, err := asn1.Marshal(androidRootOfTrust{
		VerifiedBootKey: []byte("trusted-boot-key"), DeviceLocked: locked,
		VerifiedBootState: androidVerifiedBootState, VerifiedBootHash: []byte("verified-boot-hash"),
	})
	if err != nil {
		t.Fatal(err)
	}
	packageDER, err := asn1.Marshal(androidAttestationApplicationID{
		PackageInfos:     []androidAttestationPackageInfo{{PackageName: []byte("com.gorapeflutter.gf_app"), Version: 1}},
		SignatureDigests: [][]byte{digest},
	})
	if err != nil {
		t.Fatal(err)
	}
	tee := map[int]asn1.RawValue{
		androidTagPurpose:      androidExplicitSet(t, androidPurposeSign, androidPurposeVerify),
		androidTagAlgorithm:    androidExplicit(t, androidAlgorithmEC),
		androidTagKeySize:      androidExplicit(t, 256),
		androidTagDigest:       androidExplicitSet(t, androidDigestSHA256),
		androidTagECurve:       androidExplicit(t, androidCurveP256),
		androidTagOrigin:       androidExplicit(t, androidOriginGenerated),
		androidTagRootOfTrust:  androidExplicitRaw(t, rootDER),
		androidTagOSVersion:    androidExplicit(t, osVersion),
		androidTagOSPatchLevel: androidExplicit(t, osPatch),
		androidTagVendorPatch:  androidExplicit(t, vendorPatch),
		androidTagBootPatch:    androidExplicit(t, bootPatch),
	}
	software := map[int]asn1.RawValue{
		androidTagApplicationID: androidExplicitOctets(t, packageDER),
	}
	return keyDescription{
		AttestationSecurityLevel: 1,
		KeymasterSecurityLevel:   1,
		SoftwareEnforced:         marshalAndroidAuthorizationList(t, software),
		TEEEnforced:              marshalAndroidAuthorizationList(t, tee),
	}
}

func marshalAndroidAuthorizationList(t *testing.T, fields map[int]asn1.RawValue) asn1.RawValue {
	t.Helper()
	encoded := make([]byte, 0)
	for tag := 1; tag <= 719; tag++ {
		field, ok := fields[tag]
		if !ok {
			continue
		}
		field.Tag = tag
		part, err := asn1.Marshal(field)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, part...)
	}
	full, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: encoded})
	if err != nil {
		t.Fatal(err)
	}
	var value asn1.RawValue
	if _, err = asn1.Unmarshal(full, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func androidExplicit(t *testing.T, value any) asn1.RawValue {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return androidExplicitRaw(t, encoded)
}

func androidExplicitSet(t *testing.T, values ...int) asn1.RawValue {
	t.Helper()
	encoded := make([]byte, 0)
	for _, value := range values {
		item, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, item...)
	}
	set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: encoded})
	if err != nil {
		t.Fatal(err)
	}
	return androidExplicitRaw(t, set)
}

func androidExplicitOctets(t *testing.T, value []byte) asn1.RawValue {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return androidExplicitRaw(t, encoded)
}

func androidExplicitRaw(t *testing.T, encoded []byte) asn1.RawValue {
	t.Helper()
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: encoded}
}
