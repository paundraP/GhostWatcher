package threatintel

const (
	ShlayerHash = "8f32f0f1086f954eceda8ce9b8f6a8d89f5cb9184160a95c31a01d10b191ed32"
	AdloadHash  = "268f355f8fda7058118f418fce477f4f65774c8b95ddf53f9b2d2e7f930f77f2"
	XCSSETHash  = "58b1f4ec3ecaf24a2b45af633d8f8fdf2b7f3f278f8e88792f0dd7be8f45f198"
)

func DefaultHashes() map[string]string {
	return map[string]string{
		ShlayerHash: "Shlayer",
		AdloadHash:  "Adload",
		XCSSETHash:  "XCSSET",
	}
}
