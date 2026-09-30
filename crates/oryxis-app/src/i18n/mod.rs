use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_LANG: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_LAYOUT_DIR: AtomicUsize = AtomicUsize::new(0);

/// User-facing setting controlling the visual layout direction. `Auto` follows
/// the active language (so Persian flips automatically); the explicit values
/// override regardless of the chosen language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutDirection {
    Auto,
    LeftToRight,
    RightToLeft,
}

impl LayoutDirection {
    pub const ALL: &[LayoutDirection] = &[
        Self::Auto,
        Self::LeftToRight,
        Self::RightToLeft,
    ];

    pub fn code(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::LeftToRight => "ltr",
            Self::RightToLeft => "rtl",
        }
    }

    pub fn from_code(code: &str) -> Self {
        match code {
            "ltr" => Self::LeftToRight,
            "rtl" => Self::RightToLeft,
            _ => Self::Auto,
        }
    }

    /// i18n key used for the dropdown label of this option.
    pub fn label_key(&self) -> &'static str {
        match self {
            Self::Auto => "layout_dir_auto",
            Self::LeftToRight => "layout_dir_ltr",
            Self::RightToLeft => "layout_dir_rtl",
        }
    }

    pub fn set_active(dir: LayoutDirection) {
        let idx = Self::ALL.iter().position(|d| *d == dir).unwrap_or(0);
        ACTIVE_LAYOUT_DIR.store(idx, Ordering::Relaxed);
    }

    pub fn active() -> LayoutDirection {
        let idx = ACTIVE_LAYOUT_DIR.load(Ordering::Relaxed);
        Self::ALL.get(idx).copied().unwrap_or(LayoutDirection::Auto)
    }
}

/// True when the active *language* uses right-to-left script. Drives text
/// alignment, text-input direction, BiDi hints. Independent of the user's
/// layout-direction setting, Persian text is always RTL regardless of
/// whether the user kept the sidebar on the left.
///
/// Currently unused at call sites, cosmic-text's BiDi shaping handles
/// glyph-level rendering automatically. Exposed for future per-widget
/// alignment overrides (e.g. right-aligning RTL `text_input`s).
#[allow(dead_code)]
pub fn is_rtl_text() -> bool {
    Language::active().is_rtl()
}

/// True when the *layout* should be physically mirrored (sidebar swaps
/// sides, row children reverse). Resolves the user's `LayoutDirection`
/// setting; `Auto` defers to the language. Override `Auto` with explicit
/// `Left`/`Right` if the user wants Persian text but a familiar layout.
pub fn is_rtl_layout() -> bool {
    match LayoutDirection::active() {
        LayoutDirection::Auto => Language::active().is_rtl(),
        LayoutDirection::LeftToRight => false,
        LayoutDirection::RightToLeft => true,
    }
}

/// Resolve the OS locale to a supported language, English when nothing
/// matches. Walks the OS preference *list* (macOS exposes several;
/// Windows / Linux typically one) so a user whose first choice we don't
/// ship still lands on their second instead of English. Cached for the
/// session: the boot path and the Settings picker share one lookup, and
/// an OS locale change takes effect on the next launch.
pub fn detect_os_language() -> Language {
    use std::sync::OnceLock;
    static DETECTED: OnceLock<Language> = OnceLock::new();
    *DETECTED.get_or_init(|| {
        sys_locale::get_locales()
            .find_map(|tag| Language::for_locale(&tag))
            .unwrap_or(Language::English)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    PortugueseBR,
    Spanish,
    French,
    German,
    Italian,
    Chinese,
    Japanese,
    Russian,
    Persian,
    Arabic,
    Korean,
    Polish,
    Turkish,
    Indonesian,
    Vietnamese,
    Ukrainian,
    Hebrew,
    ChineseTraditional,
    Thai,
    Hindi,
    Czech,
    Greek,
}

impl Language {
    pub const ALL: &[Language] = &[
        Self::English,
        Self::PortugueseBR,
        Self::Spanish,
        Self::French,
        Self::German,
        Self::Italian,
        Self::Chinese,
        Self::Japanese,
        Self::Russian,
        Self::Persian,
        Self::Arabic,
        Self::Korean,
        Self::Polish,
        Self::Turkish,
        Self::Indonesian,
        Self::Vietnamese,
        Self::Ukrainian,
        Self::Hebrew,
        Self::ChineseTraditional,
        Self::Thai,
        Self::Hindi,
        Self::Czech,
        Self::Greek,
    ];

    pub fn code(&self) -> &'static str {
        match self {
            Self::English => "en",
            Self::PortugueseBR => "pt-BR",
            Self::Spanish => "es",
            Self::French => "fr",
            Self::German => "de",
            Self::Italian => "it",
            Self::Chinese => "zh",
            Self::Japanese => "ja",
            Self::Russian => "ru",
            Self::Persian => "fa",
            Self::Arabic => "ar",
            Self::Korean => "ko",
            Self::Polish => "pl",
            Self::Turkish => "tr",
            Self::Indonesian => "id",
            Self::Vietnamese => "vi",
            Self::Ukrainian => "uk",
            Self::Hebrew => "he",
            Self::ChineseTraditional => "zh-TW",
            Self::Thai => "th",
            Self::Hindi => "hi",
            Self::Czech => "cs",
            Self::Greek => "el",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::English => "English",
            Self::PortugueseBR => "Português (Brasil)",
            Self::Spanish => "Español",
            Self::French => "Français",
            Self::German => "Deutsch",
            Self::Italian => "Italiano",
            Self::Chinese => "简体中文",
            Self::Japanese => "日本語",
            Self::Russian => "Русский",
            Self::Persian => "فارسی",
            Self::Arabic => "العربية",
            Self::Korean => "한국어",
            Self::Polish => "Polski",
            Self::Turkish => "Türkçe",
            Self::Indonesian => "Bahasa Indonesia",
            Self::Vietnamese => "Tiếng Việt",
            Self::Ukrainian => "Українська",
            Self::Hebrew => "עברית",
            Self::ChineseTraditional => "繁體中文",
            Self::Thai => "ไทย",
            Self::Hindi => "हिन्दी",
            Self::Czech => "Čeština",
            Self::Greek => "Ελληνικά",
        }
    }

    /// Whether this language is written right-to-left. Used by the
    /// `LayoutDirection::Auto` setting to decide if the UI should mirror.
    pub fn is_rtl(&self) -> bool {
        matches!(self, Self::Persian | Self::Arabic | Self::Hebrew)
    }

    /// Map a BCP-47 locale tag from the OS (e.g. "pt-BR", "es_MX",
    /// "zh-Hant-TW") to a supported language, or `None` when nothing
    /// matches so the caller can walk the OS preference list before
    /// falling back to English. Matching order: Chinese first (the
    /// script / region subtag decides Simplified vs Traditional, a
    /// primary-subtag match would collapse zh-HK into Simplified),
    /// then the exact tag, then the primary subtag alone ("es-MX" ->
    /// Spanish; "pt-PT" -> the only Portuguese we ship).
    pub fn for_locale(tag: &str) -> Option<Self> {
        let norm = tag.trim().replace('_', "-").to_ascii_lowercase();
        let mut parts = norm.split('-');
        let primary = match parts.next().unwrap_or("") {
            // Legacy ISO-639 codes some platforms still report.
            "iw" => "he",
            "in" => "id",
            p => p,
        };
        if primary.is_empty() {
            return None;
        }
        if primary == "zh" {
            let traditional =
                parts.any(|p| matches!(p, "hant" | "tw" | "hk" | "mo"));
            return Some(if traditional {
                Self::ChineseTraditional
            } else {
                Self::Chinese
            });
        }
        Self::ALL
            .iter()
            .copied()
            .find(|l| l.code().eq_ignore_ascii_case(&norm))
            .or_else(|| {
                Self::ALL.iter().copied().find(|l| {
                    l.code()
                        .split('-')
                        .next()
                        .is_some_and(|c| c.eq_ignore_ascii_case(primary))
                })
            })
    }

    pub fn from_code(code: &str) -> Self {
        match code {
            "pt-BR" => Self::PortugueseBR,
            "es" => Self::Spanish,
            "fr" => Self::French,
            "de" => Self::German,
            "it" => Self::Italian,
            "zh" => Self::Chinese,
            "ja" => Self::Japanese,
            "ru" => Self::Russian,
            "fa" => Self::Persian,
            "ar" => Self::Arabic,
            "ko" => Self::Korean,
            "pl" => Self::Polish,
            "tr" => Self::Turkish,
            "id" => Self::Indonesian,
            "vi" => Self::Vietnamese,
            "uk" => Self::Ukrainian,
            "he" => Self::Hebrew,
            "zh-TW" => Self::ChineseTraditional,
            "th" => Self::Thai,
            "hi" => Self::Hindi,
            "cs" => Self::Czech,
            "el" => Self::Greek,
            _ => Self::English,
        }
    }

    pub fn set_active(lang: Language) {
        let idx = Self::ALL.iter().position(|l| *l == lang).unwrap_or(0);
        ACTIVE_LANG.store(idx, Ordering::Relaxed);
    }

    pub fn active() -> Language {
        let idx = ACTIVE_LANG.load(Ordering::Relaxed);
        Self::ALL.get(idx).copied().unwrap_or(Language::English)
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

mod en;
mod pt_br;
mod es;
mod fr;
mod de;
mod it;
mod zh;
mod ja;
mod ru;
mod fa;
mod ar;
mod ko;
mod pl;
mod tr;
mod id;
mod vi;
mod uk;
mod he;
mod zh_tw;
mod th;
mod hi;
mod cs;
mod el;

/// Get a translated string. Usage: `t("hosts")` or `t("create_host")`
pub fn t(key: &str) -> &'static str {
    let lang = Language::active();
    translate(key, lang)
}

/// Fill a translated template's `{name}` placeholders in ONE pass, so a
/// substituted value (a username, a raw server diagnostic) that happens
/// to contain `{user}` is kept verbatim instead of being expanded by the
/// next replacement, and a translation may reorder its parameters. An
/// unknown placeholder is left as written.
/// Usage: `t_fill("ssh_progress_authenticated", &[("user", &name)])`.
pub fn t_fill(key: &str, values: &[(&str, &str)]) -> String {
    fill(t(key), values)
}

pub(crate) fn fill(mut template: &str, values: &[(&str, &str)]) -> String {
    let mut result = String::with_capacity(template.len());
    while let Some(start) = template.find('{') {
        result.push_str(&template[..start]);
        template = &template[start..];
        let Some(end) = template.find('}') else {
            break;
        };
        let name = &template[1..end];
        let replacement = values
            .iter()
            .find(|(key, _)| *key == name)
            .map_or(&template[..=end], |(_, value)| *value);
        result.push_str(replacement);
        template = &template[end + 1..];
    }
    result.push_str(template);
    result
}

/// English lookup, independent of the active-language global. Used by
/// coverage tests that assert a key resolves (English is the table that
/// always returns a value, `"???"` for an unknown key) and by the
/// Settings search, which matches queries against the English label in
/// addition to the active language.
pub(crate) fn en_lookup(key: &str) -> &'static str {
    en::lookup(key)
}

/// Localized "Open in <file manager>" label using the OS-native name:
/// File Explorer on Windows, Finder on macOS, the generic file manager
/// elsewhere. The generic "File Manager" wording is wrong on Windows /
/// macOS, where users expect the platform app name.
pub fn open_in_file_manager_label() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        t("open_in_explorer")
    }
    #[cfg(target_os = "macos")]
    {
        t("open_in_finder")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        t("open_in_file_manager")
    }
}

/// "1 host" / "N hosts" with the count inlined. One/other is an
/// approximation (Slavic languages have richer plural classes), good
/// enough for a count label, and it fixes the "1 hosts" card subtitle.
/// "1 snippet" / "N snippets", same one/other approximation as
/// [`host_count`]. Used by the snippet group folder cards.
pub fn snippet_count(n: usize) -> String {
    if n == 1 {
        t("snippet_count_one").to_string()
    } else {
        format!("{} {}", n, t("snippet_count_other"))
    }
}

pub fn host_count(n: usize) -> String {
    if n == 1 {
        t("host_count_one").to_string()
    } else {
        format!("{} {}", n, t("host_count_other"))
    }
}

/// "1 line" / "N lines" with the count inlined, same one/other
/// approximation as [`host_count`]. Used by the careful-paste dialog.
pub fn line_count(n: usize) -> String {
    if n == 1 {
        t("line_count_one").to_string()
    } else {
        format!("{} {}", n, t("line_count_other"))
    }
}

fn translate(key: &str, lang: Language) -> &'static str {
    match lang {
        Language::English => en::lookup(key),
        Language::PortugueseBR => pt_br::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Spanish => es::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::French => fr::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::German => de::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Italian => it::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Chinese => zh::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Japanese => ja::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Russian => ru::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Persian => fa::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Arabic => ar::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Korean => ko::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Polish => pl::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Turkish => tr::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Indonesian => id::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Vietnamese => vi::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Ukrainian => uk::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Hebrew => he::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::ChineseTraditional => zh_tw::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Thai => th::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Hindi => hi::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Czech => cs::lookup(key).unwrap_or_else(|| en::lookup(key)),
        Language::Greek => el::lookup(key).unwrap_or_else(|| en::lookup(key)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_progress_translations_cover_every_locale_and_keep_their_placeholders() {
        type Lookup = fn(&str) -> Option<&'static str>;
        let locales: &[(&str, Lookup)] = &[
            ("en", |key| Some(en::lookup(key))),
            ("zh", zh::lookup),
            ("zh_tw", zh_tw::lookup),
            ("de", de::lookup),
            ("fr", fr::lookup),
            ("es", es::lookup),
            ("pt_br", pt_br::lookup),
            ("it", it::lookup),
            ("ja", ja::lookup),
            ("ko", ko::lookup),
            ("ru", ru::lookup),
            ("uk", uk::lookup),
            ("pl", pl::lookup),
            ("tr", tr::lookup),
            ("id", id::lookup),
            ("vi", vi::lookup),
            ("th", th::lookup),
            ("hi", hi::lookup),
            ("cs", cs::lookup),
            ("el", el::lookup),
            ("ar", ar::lookup),
            ("fa", fa::lookup),
            ("he", he::lookup),
        ];
        let keys = [
            "ssh_progress_start",
            "ssh_progress_connecting",
            "ssh_progress_handshake",
            "ssh_progress_authenticating",
            "ssh_progress_authenticated",
            "ssh_progress_opening_session",
            "ssh_progress_connection_failed",
            "ssh_progress_auth_failed",
            "ssh_progress_session_failed",
            "ssh_progress_jump_hosts",
            "ssh_progress_proxy",
            "ssh_progress_command_proxy",
            "ssh_progress_forwards",
            "ssh_progress_instance_connect",
            "ssh_progress_instance_connect_failed",
            "ssh_progress_pane_connecting",
            "ssh_progress_error",
            "ssh_progress_method_auto",
            "ssh_progress_method_password",
            "ssh_progress_method_password_prompt",
            "ssh_progress_method_key",
            "ssh_progress_method_agent",
            "ssh_progress_method_interactive",
            "ssh_progress_method_certificate",
            "ssh_progress_method_security_key",
        ];
        fn placeholders(text: &str) -> std::collections::BTreeSet<&str> {
            text.split('{')
                .skip(1)
                .filter_map(|part| part.split_once('}').map(|(name, _)| name))
                .collect()
        }
        assert_eq!(locales.len(), Language::ALL.len());
        for (locale, lookup) in locales {
            for key in keys {
                let text = lookup(key).unwrap_or_else(|| panic!("{locale} is missing {key}"));
                assert_eq!(
                    placeholders(text),
                    placeholders(en::lookup(key)),
                    "{locale}: {key}",
                );
            }
        }
    }

    #[test]
    fn fill_reorders_parameters_without_rewriting_substituted_text() {
        assert_eq!(
            fill("{method}: {user}", &[("user", "name{method}"), ("method", "密钥")]),
            "密钥: name{method}",
        );
        assert_eq!(
            fill("{user}: {error}", &[("user", "root"), ("error", "拒绝 {user}: 🔑")]),
            "root: 拒绝 {user}: 🔑",
        );
        assert_eq!(fill("{unknown} {", &[("user", "x")]), "{unknown} {");
    }

    /// Every supported code resolves to itself, regardless of case or
    /// the `_` separator some platforms use.
    #[test]
    fn for_locale_roundtrips_every_supported_code() {
        for lang in Language::ALL {
            assert_eq!(Language::for_locale(lang.code()), Some(*lang));
            assert_eq!(
                Language::for_locale(&lang.code().to_ascii_uppercase()),
                Some(*lang)
            );
            assert_eq!(
                Language::for_locale(&lang.code().replace('-', "_")),
                Some(*lang)
            );
        }
    }

    /// Region / script variants fall back to the primary subtag.
    #[test]
    fn for_locale_matches_primary_subtag() {
        assert_eq!(Language::for_locale("en-GB"), Some(Language::English));
        assert_eq!(Language::for_locale("es-MX"), Some(Language::Spanish));
        assert_eq!(Language::for_locale("fr-CA"), Some(Language::French));
        assert_eq!(Language::for_locale("de-AT"), Some(Language::German));
        // pt-BR is the only Portuguese we ship; European Portuguese
        // must land on it, not on English.
        assert_eq!(
            Language::for_locale("pt-PT"),
            Some(Language::PortugueseBR)
        );
        assert_eq!(
            Language::for_locale("pt_PT"),
            Some(Language::PortugueseBR)
        );
    }

    /// Chinese needs the script / region subtag: a primary-only match
    /// would collapse Hong Kong / Taiwan into Simplified.
    #[test]
    fn for_locale_disambiguates_chinese() {
        assert_eq!(Language::for_locale("zh"), Some(Language::Chinese));
        assert_eq!(Language::for_locale("zh-CN"), Some(Language::Chinese));
        assert_eq!(Language::for_locale("zh-SG"), Some(Language::Chinese));
        assert_eq!(
            Language::for_locale("zh-Hans-SG"),
            Some(Language::Chinese)
        );
        assert_eq!(
            Language::for_locale("zh-TW"),
            Some(Language::ChineseTraditional)
        );
        assert_eq!(
            Language::for_locale("zh-HK"),
            Some(Language::ChineseTraditional)
        );
        assert_eq!(
            Language::for_locale("zh-MO"),
            Some(Language::ChineseTraditional)
        );
        assert_eq!(
            Language::for_locale("zh-Hant-HK"),
            Some(Language::ChineseTraditional)
        );
    }

    /// Legacy ISO-639 codes still reported by some platforms.
    #[test]
    fn for_locale_maps_legacy_codes() {
        assert_eq!(Language::for_locale("iw-IL"), Some(Language::Hebrew));
        assert_eq!(Language::for_locale("in-ID"), Some(Language::Indonesian));
    }

    /// Unsupported / degenerate tags yield None so the caller can try
    /// the next OS preference before defaulting to English.
    #[test]
    fn for_locale_rejects_unsupported_tags() {
        assert_eq!(Language::for_locale(""), None);
        assert_eq!(Language::for_locale("C"), None);
        assert_eq!(Language::for_locale("POSIX"), None);
        assert_eq!(Language::for_locale("xx-XX"), None);
        assert_eq!(Language::for_locale("gsw-CH"), None);
    }
}
