package operator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func TestTranslate_SecurityContextFromSpec(t *testing.T) {
	uid, gid, fsg := int64(1000), int64(1000), int64(1000)
	nonRoot := true
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version:   "1.0.0",
		Image:     v1alpha1.WorkloadImage{Ref: "myapp:v1"},
		Resources: v1alpha1.WorkloadResources{VCPUs: 1, MemoryMb: 256, DiskGb: 5},
		Network:   &v1alpha1.WorkloadNetwork{Access: "none"},
		Security: &v1alpha1.WorkloadSecurity{
			RunAsUser:    &uid,
			RunAsGroup:   &gid,
			FsGroup:      &fsg,
			RunAsNonRoot: &nonRoot,
		},
	}
	result, err := Translate(spec, TranslateOpts{InstanceId: "inst-sec", WorkloadName: "sec-wl", Namespace: "default"})
	require.NoError(t, err)

	sc := result.Pod.Spec.SecurityContext
	require.NotNil(t, sc)
	require.NotNil(t, sc.RunAsUser)
	assert.Equal(t, int64(1000), *sc.RunAsUser)
	require.NotNil(t, sc.RunAsGroup)
	assert.Equal(t, int64(1000), *sc.RunAsGroup)
	require.NotNil(t, sc.FSGroup)
	assert.Equal(t, int64(1000), *sc.FSGroup)
	require.NotNil(t, sc.RunAsNonRoot)
	assert.True(t, *sc.RunAsNonRoot)
	// Hardened defaults are preserved alongside the overrides.
	require.NotNil(t, sc.SeccompProfile)
	assert.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, sc.SeccompProfile.Type)
}

func TestTranslate_SecurityContextDefaultsWhenUnset(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version:   "1.0.0",
		Image:     v1alpha1.WorkloadImage{Ref: "x:1"},
		Resources: v1alpha1.WorkloadResources{VCPUs: 1, MemoryMb: 128, DiskGb: 1},
		Network:   &v1alpha1.WorkloadNetwork{Access: "none"},
	}
	result, err := Translate(spec, TranslateOpts{InstanceId: "i", WorkloadName: "w", Namespace: "default"})
	require.NoError(t, err)

	sc := result.Pod.Spec.SecurityContext
	require.NotNil(t, sc)
	assert.Nil(t, sc.RunAsUser, "no runAsUser unless spec.Security sets it")
	assert.Nil(t, sc.FSGroup, "no fsGroup unless spec.Security sets it")
	assert.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, sc.SeccompProfile.Type)
}
