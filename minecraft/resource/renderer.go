package resource

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/df-mc/jsonc"
)

// ClientEntityIdentifiers returns client entity identifiers from the base pack
// and every subpack. It does not resolve which definition wins for a client.
// An encrypted pack or an unreadable entity file returns an error.
func (p *Pack) ClientEntityIdentifiers() ([]string, error) {
	files, err := p.rendererFiles("entity")
	if err != nil {
		return nil, err
	}
	var identifiers []string
	for _, name := range files {
		data, err := p.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var entity struct {
			Entity struct {
				Description struct {
					Identifier string `json:"identifier"`
				} `json:"description"`
			} `json:"minecraft:client_entity"`
		}
		if err := jsonc.Unmarshal(data, &entity); err != nil {
			return nil, fmt.Errorf("read client entity %q: %w", name, err)
		}
		if id := entity.Entity.Description.Identifier; id != "" {
			identifiers = append(identifiers, id)
		}
	}
	return identifiers, nil
}

// RenderControllerIdentifiers returns render controller identifiers from the
// base pack and every subpack, without resolving precedence. An encrypted pack
// or an unreadable controller file returns an error.
func (p *Pack) RenderControllerIdentifiers() ([]string, error) {
	files, err := p.rendererFiles("render_controllers")
	if err != nil {
		return nil, err
	}
	var identifiers []string
	for _, name := range files {
		data, err := p.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var controllers struct {
			Controllers map[string]json.RawMessage `json:"render_controllers"`
		}
		if err := jsonc.Unmarshal(data, &controllers); err != nil {
			return nil, fmt.Errorf("read render controllers %q: %w", name, err)
		}
		for id := range controllers.Controllers {
			identifiers = append(identifiers, id)
		}
	}
	return identifiers, nil
}

// rendererFiles collects one resource directory at the base and in each
// subpack, keeping archive paths relative to the pack's manifest directory.
func (p *Pack) rendererFiles(dir string) ([]string, error) {
	if p.Encrypted() {
		return nil, fmt.Errorf("cannot inspect encrypted resource pack")
	}
	files, err := p.ResourceFiles(dir)
	if err != nil {
		return nil, err
	}
	subpacks, err := p.ResourceFiles("subpacks")
	if err != nil {
		return nil, err
	}
	for _, name := range subpacks {
		parts := strings.Split(name, "/")
		if len(parts) >= 4 && strings.EqualFold(parts[2], dir) {
			files = append(files, name)
		}
	}
	return files, nil
}
