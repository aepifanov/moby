package container

// ResizeOptions holds parameters to resize a TTY.
// It can be used to resize container TTYs and
// exec process TTYs too.
type ResizeOptions struct {
	Height uint
	Width  uint
}
