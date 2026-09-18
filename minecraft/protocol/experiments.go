package protocol

// ExperimentData holds data on an experiment that is either enabled or disabled.
type ExperimentData struct {
	// Name is the name of the experiment.
	Name string
	// Enabled specifies if the experiment is enabled. Vanilla typically always sets this to true for any
	// experiments sent.
	Enabled bool
}

// Marshal reads or writes ExperimentData using its canonical wire layout.
func (x *ExperimentData) Marshal(io IO) {
	io.String(&x.Name)
	io.Bool(&x.Enabled)
}
