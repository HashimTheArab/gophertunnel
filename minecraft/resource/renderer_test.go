package resource

import (
	"slices"
	"testing"
)

// TestPack_RendererIdentifiersIncludesSubpacks verifies resource semantics without
// prescribing the renderer admission or precedence policy of a consumer.
func TestPack_RendererIdentifiersIncludesSubpacks(t *testing.T) {
	for _, prefix := range []string{"", "nested/"} {
		t.Run(prefix, func(t *testing.T) {
			files := map[string]string{
				prefix + "manifest.json": testManifest,
				prefix + "Entity/base.json": `// comment
{"minecraft:client_entity":{"description":{"identifier":"minecraft:zombie"}}}`,
				prefix + "render_controllers/base.json":                 `{"render_controllers":{"controller.render.zombie":{}}}`,
				prefix + "subpacks/high/ENTITY/player.json":             `{"minecraft:client_entity":{"description":{"identifier":"minecraft:player"}}}`,
				prefix + "subpacks/high/Render_Controllers/player.json": `{"render_controllers":{"controller.render.player.third_person":{}}}`,
				prefix + "subpacks/low/textures/irrelevant.txt":         "not JSON",
				prefix + "models/ignored.json":                          `{"minecraft:client_entity":{"description":{"identifier":"ignored"}}}`,
			}
			p, err := ReadBytes(packArchive(t, files))
			if err != nil {
				t.Fatal(err)
			}
			entities, err := p.ClientEntityIdentifiers()
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(entities)
			if !slices.Equal(entities, []string{"minecraft:player", "minecraft:zombie"}) {
				t.Fatalf("entities = %v", entities)
			}
			controllers, err := p.RenderControllerIdentifiers()
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(controllers)
			if !slices.Equal(controllers, []string{"controller.render.player.third_person", "controller.render.zombie"}) {
				t.Fatalf("controllers = %v", controllers)
			}
			if _, err := p.WithContentKey("encrypted").ClientEntityIdentifiers(); err == nil {
				t.Fatal("encrypted entity inspection succeeded")
			}
			if _, err := p.WithContentKey("encrypted").RenderControllerIdentifiers(); err == nil {
				t.Fatal("encrypted controller inspection succeeded")
			}
		})
	}
}

// TestPack_RendererIdentifiersRejectUnreadableFiles covers the base and subpack paths.
func TestPack_RendererIdentifiersRejectUnreadableFiles(t *testing.T) {
	for _, dir := range []string{"entity", "render_controllers", "subpacks/high/entity", "subpacks/high/render_controllers"} {
		t.Run(dir, func(t *testing.T) {
			p, err := ReadBytes(packArchive(t, map[string]string{"manifest.json": testManifest, dir + "/bad.json": "{invalid"}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.ClientEntityIdentifiers(); err == nil && (dir == "entity" || dir == "subpacks/high/entity") {
				t.Fatal("bad entity accepted")
			}
			if _, err := p.RenderControllerIdentifiers(); err == nil && (dir == "render_controllers" || dir == "subpacks/high/render_controllers") {
				t.Fatal("bad controller accepted")
			}
		})
	}
}
