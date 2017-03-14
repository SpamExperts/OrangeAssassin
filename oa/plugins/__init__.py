"""Package reserved for handling PAD plugins."""

# XXX This should be loaded from a configuration file.
# Plugins reimplemented from Perl to Python.
REIMPLEMENTED_PLUGINS = {
    "Mail::SpamAssassin::Plugin::DumpText":
        "oa.plugins.dump_text.DumpText",
    "Mail::SpamAssassin::Plugin::Pyzor":
        "oa.plugins.pyzor.PyzorPlugin",
    "Mail::SpamAssassin::Plugin::WhiteListSubject":
        "oa.plugins.whitelist_subject.WhiteListSubjectPlugin",
    "Mail::SpamAssassin::Plugin::ImageInfo":
        "oa.plugins.image_info.ImageInfoPlugin",
    "Mail::SpamAssassin::Plugin::RelayCountry":
        "oa.plugins.relay_country.RelayCountryPlugin",
    "Mail::SpamAssassin::Plugin::URIDetail":
        "oa.plugins.uri_detail.URIDetailPlugin",
    "Mail::SpamAssassin::Plugin::TextCat":
        "oa.plugins.textcat.TextCatPlugin",
    "Mail::SpamAssassin::Plugin::AWL":
        "oa.plugins.awl.AutoWhiteListPlugin",
    "Mail::SpamAssassin::Plugin::ReplaceTags":
        "oa.plugins.replace_tags.ReplaceTags",
    "Mail::SpamAssassin::Plugin::Shortcircuit":
        "oa.plugins.short_circuit.ShortCircuit",
    "Mail::SpamAssassin::Plugin::BodyEval":
        "oa.plugins.body_eval.BodyEval",
    "Mail::SpamAssassin::Plugin::DNSEval":
        "oa.plugins.dns_eval.DNSEval",
    "Mail::SpamAssassin::Plugin::SPF":
        "oa.plugins.spf.SpfPlugin",
    "Mail::SpamAssassin::Plugin::WLBLEval":
        "oa.plugins.wlbl_eval.WLBLEvalPlugin",
    "Mail::SpamAssassin::Plugin::Razor2":
        "oa.plugins.razor2.Razor2Plugin",
    "Mail::SpamAssassin::Plugin::FreeMail":
        "oa.plugins.free_mail.FreeMail",
    "Mail::SpamAssassin::Plugin::SpamCop":
        "oa.plugins.spam_cop.SpamCopPlugin",
    "Mail::SpamAssassin::Plugin::RelayEval":
        "oa.plugins.relay_eval.RelayEval",
    "Mail::SpamAssassin::Plugin::HeaderEval":
        "oa.plugins.header_eval.HeaderEval",
    "Mail::SpamAssassin::Plugin::DKIM":
        "oa.plugins.dkim.DKIMPlugin",
    "Mail::SpamAssassin::Plugin::MIMEEval":
        "oa.plugins.mime_eval.MIMEEval",
    "Mail::SpamAssassin::Plugin::URIEval":
        "oa.plugins.uri_eval.URIEvalPlugin",
    "Mail::SpamAssassin::Plugin::AutoLearnThreshold":
        "oa.plugins.auto_learn_threshold.AutoLearnThreshold",
}
