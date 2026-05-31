package i18n

import (
	"testing"
)

func TestDetectLang(t *testing.T) {
	lang := DetectLang()
	if lang == "" {
		t.Errorf("DetectLang() returned empty string")
	}
}

func TestTranslator_FallbackToEnglish(t *testing.T) {
	// English translator basic functionality
	translator := NewTranslator("en")
	if translator.T("cpu") != "CPU" {
		t.Errorf("Expected 'CPU', got %s", translator.T("cpu"))
	}

	// Unknown language should fall back to English
	unknownTranslator := NewTranslator("unknown_lang")
	if unknownTranslator.T("cpu") != "CPU" {
		t.Errorf("Expected 'CPU', got %s", unknownTranslator.T("cpu"))
	}

	// Missing key fallback
	if unknownTranslator.T("missing_key_that_does_not_exist") != "missing_key_that_does_not_exist" {
		t.Errorf("Expected raw key for missing translation")
	}
}
