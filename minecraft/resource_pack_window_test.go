package minecraft

import (
	"slices"
	"testing"
)

func TestResourcePackChunkWindow_ProcessingBoundsRequests(t *testing.T) {
	w, err := NewResourcePackChunkWindow(10, 3, ResourcePackDownloadConfig{MaxInFlightChunks: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := w.Requests(); !slices.Equal(got, []uint32{0, 1}) {
		t.Fatalf("requests %v", got)
	}
	if err := w.Accept(1, 3); err != nil {
		t.Fatal(err)
	}
	if got := w.Requests(); len(got) != 0 {
		t.Fatalf("buffered chunk released its slot: %v", got)
	}
	if err := w.Consumed(1); err != nil {
		t.Fatal(err)
	}
	if got := w.Requests(); !slices.Equal(got, []uint32{2}) {
		t.Fatalf("out-of-order chunk did not release a slot: %v", got)
	}
	for _, index := range []uint32{2, 0} {
		if err := w.Accept(index, 3); err != nil {
			t.Fatal(err)
		}
		if err := w.Consumed(index); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.Requests(); !slices.Equal(got, []uint32{3}) {
		t.Fatalf("tail request %v", got)
	}
	if w.Done() {
		t.Fatal("completed before tail")
	}
	if err := w.Accept(3, 1); err != nil {
		t.Fatal(err)
	}
	if w.Done() {
		t.Fatal("completed before consuming tail")
	}
	if err := w.Consumed(3); err != nil {
		t.Fatal(err)
	}
	if !w.Done() {
		t.Fatal("did not complete")
	}
}

func TestResourcePackChunkWindow_RejectsInvalidResponses(t *testing.T) {
	w, err := NewResourcePackChunkWindow(4, 2, ResourcePackDownloadConfig{MaxInFlightChunks: 1})
	if err != nil {
		t.Fatal(err)
	}
	w.Requests()
	for _, test := range []struct {
		name   string
		index  uint32
		length int
	}{{"unrequested", 1, 2}, {"out of range", 2, 2}, {"short", 0, 1}, {"negative", 0, -1}} {
		t.Run(test.name, func(t *testing.T) {
			if err := w.Accept(test.index, test.length); err == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
	if err := w.Consumed(0); err == nil {
		t.Fatal("consumed before accepting")
	}
	if err := w.Accept(0, 2); err != nil {
		t.Fatal(err)
	}
	if err := w.Accept(0, 2); err == nil {
		t.Fatal("accepted duplicate response")
	}
	if err := w.Consumed(0); err != nil {
		t.Fatal(err)
	}
	if err := w.Consumed(0); err == nil {
		t.Fatal("consumed duplicate response")
	}
	if got := w.Requests(); !slices.Equal(got, []uint32{1}) {
		t.Fatalf("invalid responses corrupted the window: %v", got)
	}
	if _, err := NewResourcePackChunkWindow(1, 0, ResourcePackDownloadConfig{}); err == nil {
		t.Fatal("accepted zero chunk size")
	}
}
