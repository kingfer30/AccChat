package official

type APIRequest struct {
	Messages []APIMessage `json:"messages,omitempty"`
	Prompt   any          `json:"prompt,omitempty"`
	Stream   bool         `json:"stream"`
	Model    string       `json:"model"`
	Stop     any          `json:"stop,omitempty"`
}

type APIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type TTSAPIRequest struct {
	Input  string `json:"input"`
	Voice  string `json:"voice"`
	Format string `json:"response_format"`
}
