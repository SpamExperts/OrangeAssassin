"""Package reserved for handling SA plugins."""

# XXX This should be loaded from a configuration file.
# Plugins reimplemented from Perl to Python.
REIMPLEMENTED_PLUGINS = {
    "Mail::SpamAssassin::Plugin::DumpText": "sa.plugins.dump_text.DumpText",
    "Mail::SpamAssassin::Plugin::Pyzor": "sa.plugins.pyzor.PyzorPlugin"
    "Mail::SpamAssassin::Plugin::WhiteListSubject": "sa.plugins.whitelist_subject.WhitelistSubjectPlugin"
}
