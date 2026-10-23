package libbox

// The previous pidfd workaround (go:linkname to os.checkPidfdOnce) became a
// no-op after Go 1.23+ tightened linker restrictions.
//
// Until a supported path exists, Android builds must tolerate the upstream
// pidfd behavior. Re-enable a workaround only after verifying:
//   1. https://github.com/SagerNet/sing-box/issues/3233 is still reproducible.
//   2. The Go runtime exposes a sanctioned hook (not go:linkname).
//
// Keep this file so the build tag surface stays identical across platforms.
