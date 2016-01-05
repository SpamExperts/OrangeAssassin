"""Package reserved for handling PAD plugins."""

# XXX This should be loaded from a configuration file.
# Plugins reimplemented from Perl to Python.
REIMPLEMENTED_PLUGINS = {
    "Mail::SpamAssassin::Plugin::DumpText": "pad.plugins.dump_text.DumpText",
    "Mail::SpamAssassin::Plugin::Pyzor": "pad.plugins.pyzor.PyzorPlugin",
    "Mail::SpamAssassin::Plugin::WhiteListSubject": "pad.plugins.whitelist_subject.WhiteListSubjectPlugin"
}
