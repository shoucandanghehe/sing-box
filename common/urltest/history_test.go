package urltest

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHistoryStorageLatestResult(t *testing.T) {
	storage := NewHistoryStorage()
	require.Nil(t, storage.LoadURLTestResult("node"))
	require.Nil(t, storage.LoadURLTestHistory("node"))
	storage.DeleteURLTestHistory("node")
	require.Nil(t, storage.LoadURLTestResult("node"))

	for _, step := range []struct {
		name  string
		delay uint16
		err   error
	}{
		{name: "first failure", err: errors.New("connection refused")},
		{name: "failure to zero millisecond success"},
		{name: "success to failure with empty error", err: errors.New("")},
		{name: "maximum delay is successful", delay: 65535},
	} {
		t.Run(step.name, func(t *testing.T) {
			storage.StoreURLTestResult("node", step.delay, step.err)
			result := storage.LoadURLTestResult("node")
			require.NotNil(t, result)
			require.Equal(t, step.delay, result.Delay)
			require.Equal(t, step.err, result.Error)
			require.False(t, result.Time.IsZero())
			if step.err == nil {
				require.Equal(t, &result.URLTestHistory, storage.LoadURLTestHistory("node"))
			} else {
				require.Nil(t, storage.LoadURLTestHistory("node"))
			}
		})
	}
}

func TestHistoryInvalidationPreservesLatestProbe(t *testing.T) {
	storage := NewHistoryStorage()
	storage.StoreURLTestResult("node", 37, nil)
	completed := storage.LoadURLTestResult("node")

	storage.DeleteURLTestHistory("node")
	storage.DeleteURLTestHistory("node")
	require.Nil(t, storage.LoadURLTestHistory("node"))
	require.Same(t, completed, storage.LoadURLTestResult("node"))
	require.NoError(t, completed.Error)
	require.Equal(t, uint16(37), completed.Delay)

	storage.StoreURLTestResult("node", 0, nil)
	require.NotNil(t, storage.LoadURLTestHistory("node"))
	require.Zero(t, storage.LoadURLTestHistory("node").Delay)
	require.Equal(t, uint16(37), completed.Delay)
	require.NoError(t, completed.Error)
}
