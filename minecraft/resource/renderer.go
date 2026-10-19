package resource

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"path"
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
	for _, file := range files {
		name := file.Name
		data, err := readResourceFile(file)
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
	for _, file := range files {
		name := file.Name
		data, err := readResourceFile(file)
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

// rendererFiles indexes JSON definitions at the base and in every subpack.
// It opens the archive once, so reads do not rescan unrelated pack entries.
func (p *Pack) rendererFiles(dir string) ([]*zip.File, error) {
	if p.Encrypted() {
		return nil, fmt.Errorf("cannot inspect encrypted resource pack")
	}
	entries, err := p.resourceFiles(".")
	if err != nil {
		return nil, err
	}
	root := len(pathSegments(p.manifestDir))
	var files []*zip.File
	for _, file := range entries {
		if !strings.EqualFold(path.Ext(file.Name), ".json") {
			continue
		}
		parts := strings.Split(file.Name, "/")[root:]
		base := len(parts) >= 2 && strings.EqualFold(parts[0], dir)
		subpack := len(parts) >= 4 && strings.EqualFold(parts[0], "subpacks") && strings.EqualFold(parts[2], dir)
		if base || subpack {
			files = append(files, file)
		}
	}
	return files, nil
}
