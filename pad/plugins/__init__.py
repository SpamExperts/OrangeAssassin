"""Package reserved for handling PAD plugins."""

# XXX This should be loaded from a configuration file.
# Plugins reimplemented from Perl to Python.
REIMPLEMENTED_PLUGINS = {
    "Mail::SpamAssassin::Plugin::DumpText":
        "pad.plugins.dump_text.DumpText",
    "Mail::SpamAssassin::Plugin::Pyzor":
        "pad.plugins.pyzor.PyzorPlugin",
    "Mail::SpamAssassin::Plugin::WhiteListSubject":
        "pad.plugins.whitelist_subject.WhiteListSubjectPlugin",
    "Mail::SpamAssassin::Plugin::ImageInfo":
        "pad.plugins.image_info.ImageInfoPlugin",
    "Mail::SpamAssassin::Plugin::RelayCountry":
        "pad.plugins.relay_country.RelayCountryPlugin",
    "Mail::SpamAssassin::Plugin::URIDetail":
        "pad.plugins.uri_detail.URIDetailPlugin",
    "Mail::SpamAssassin::Plugin::TextCat":
        "pad.plugins.textcat.TextCatPlugin",
    "Mail::SpamAssassin::Plugin::AWL":
        "pad.plugins.awl.AutoWhiteListPlugin",
    "Mail::SpamAssassin::Plugin::ReplaceTags":
        "pad.plugins.replace_tags.ReplaceTags",
    "Mail::SpamAssassin::Plugin::Shortcircuit":
        "pad.plugins.short_circuit.ShortCircuit"
}
