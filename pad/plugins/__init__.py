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
        "pad.plugins.short_circuit.ShortCircuit",
    "Mail::SpamAssassin::Plugin::BodyEval":
        "pad.plugins.body_eval.BodyEval",
    "Mail::SpamAssassin::Plugin::DNSEval":
        "pad.plugins.dns_eval.DNSEval",
    "Mail::SpamAssassin::Plugin::SPF":
        "pad.plugins.spf.SpfPlugin",
    "Mail::SpamAssassin::Plugin::WLBLEval":
        "pad.plugins.wlbl_eval.WLBLEvalPlugin",
    "Mail::SpamAssassin::Plugin::Razor2":
        "pad.plugins.razor2.Razor2Plugin",
    "Mail::SpamAssassin::Plugin::FreeMail":
        "pad.plugins.free_mail.FreeMail",
    "Mail::SpamAssassin::Plugin::SpamCop":
        "pad.plugins.spam_cop.SpamCopPlugin",
    "Mail::SpamAssassin::Plugin::RelayEval":
        "pad.plugins.relay_eval.RelayEval",
    "Mail::SpamAssassin::Plugin::HeaderEval":
        "pad.plugins.header_eval.HeaderEval",
    "Mail::SpamAssassin::Plugin::DKIM":
        "pad.plugins.dkim.DKIMPlugin",
    "Mail::SpamAssassin::Plugin::MIMEEval":
        "pad.plugins.mime_eval.MIMEEval",
    "Mail::SpamAssassin::Plugin::URIEval":
        "pad.plugins.uri_eval.URIEvalPlugin",
}
