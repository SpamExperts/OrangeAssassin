"""Implements the functionality to submit messages for learning when they
fall outside the defined threshold"""
from __future__ import absolute_import

import pad.plugins.base

MIN_BODY_POINTS = 3
MIN_HEADER_POINTS = 3
MIN_BODY_POINTS_LOW_THRESHOLD = -99
MIN_HEADER_POINTS_LOW_THRESHOLD = -99
LEARNER_HAM_POINTS = -1
LEARNER_SPAM_POINTS = 1


class AutoLearnThreshold(pad.plugins.base.BasePlugin):
    options = {
        "bayes_auto_learn_threshold_nonspam": ("float", 0.1),
        "bayes_auto_learn_threshold_spam": ("float", 12.0),
        "bayes_auto_learn_on_error": ("bool", False)
    }

    def valid_tests(self, tests):
        """Yields valid tests for autolearning.
         Exclude all tests flagged with noautolearn, userconf or have a 0 score
        """
        for name, rule in tests.items():
            if not rule.score:
                continue
            tflags = rule.tflags or []
            if set(tflags).intersection(["noautolearn", "userconf"]):
                self.ctxt.log.debug("Skipping test because of matching tflag")
                continue
            yield name, rule

    def bayes_agrees(self, msg):
        """Checks if the bayes plugin considered agrees with the autolearn
        plugin classification
        """
        learner_thinks_spam = self.get_local(msg, "learner_thinks_spam")
        bayes_thinks_spam = self.get_local(msg, "bayes_thinks_spam")
        bayes_thinks_ham = self.get_local(msg, "bayes_thinks_ham")
        if learner_thinks_spam and bayes_thinks_spam:
            return True
        if not learner_thinks_spam and bayes_thinks_ham:
            return True
        return False

    def should_learn(self, msg):
        """Checks if the necessary conditions for learning are met"""
        body_points = self.get_local(msg, "body_points")
        header_points = self.get_local(msg, "header_points")
        learned_points = self.get_local(msg, "learned_points")
        min_body_points = self.get_local(msg, "min_body_points")
        min_header_points = self.get_local(msg, "min_header_points")
        autolearn_forced = self.get_local(msg, "autolearn_forced")

        if self.get_local(msg, "learner_thinks_spam"):
            if header_points < min_header_points:
                self.ctxt.log.debug("not learning, header score: %s < %s",
                                    header_points, min_header_points)
                return False
            if body_points < min_body_points:
                self.ctxt.log.debug("not learning, body score: %s < %s",
                                    body_points, min_body_points)
                return False
            if learned_points < LEARNER_HAM_POINTS:
                self.ctxt.log.debug("not learning, learn score: %s < %s",
                                    learned_points, LEARNER_HAM_POINTS)
                return False
            if msg.score <= self.ctxt.conf['required_score']:
                self.ctxt.log.debug("not learning, msg score: %s < %s",
                                    msg.score, self.ctxt.conf['required_score'])
                return False
        elif self.get_local(msg, "learner_thinks_ham"):
            if learned_points > LEARNER_SPAM_POINTS:
                self.ctxt.log.debug("not learning, learn score: %s > %s",
                                    learned_points, LEARNER_SPAM_POINTS)
                return False
            if msg.score >= self.ctxt.conf['required_score']:
                self.ctxt.log.debug("not learning, msg score: %s >= %s",
                                    msg.score, self.ctxt.conf['required_score'])
                return False
        else:
            self.ctxt.log.debug(
                "not learning, autolearn score between threshold: %s",
                self.get_local(msg, "autolearn_points"))
            return False

        if self['bayes_auto_learn_on_error'] and self.bayes_agrees(msg):
            self.ctxt.log.debug("not learning, bayes agrees with classification")
            return False

        self.ctxt.log.info("Learning: score: %s min:%s, max:%s, forced: %s",
                           self.get_local(msg, "autolearn_points"),
                           self['bayes_auto_learn_threshold_nonspam'],
                           self['bayes_auto_learn_threshold_spam'],
                           autolearn_forced)
        return True

    def prepare_learning_metadata(self, msg, tests):
        """Iterates through the tests and extracts necessary information
        * l:bayes_thinks_spam if the bayes plugin test BAYES_99 is present
        * l:bayes_thinks_ham if the bayes plugin test BAYES_00 is present
        * l:header_points total score for header rules
        * l:body_points total score for header rules
        * l:learned_points total score for tests with the tflag learn
        * l:autolearn_points total score for rules except those with
            noautolearn, userconf, learn tflags
        * g:autolearn_forced if any of the rules had the flag
        * l:learner_thinks_spam if the autolearn_points is over the threshold
        * l:learner_thinks_ham if the autolearn_points is below the threshold
        * g:min_header_points minimum score that header tests must achieve
        * g:min_body_points minimum score that body tests must achieve
        """
        header_points = body_points = learn_points = points = 0
        self.set_local(msg, "bayes_thinks_spam", "BAYES_99" in tests)
        self.set_local(msg, "bayes_thinks_ham", "BAYES_00" in tests)
        autolearn_forced = False
        for name, rule in self.valid_tests(tests):
            tflags = rule.tflags or list()
            if rule.rule_type == 'header':
                header_points += rule.score
            elif rule.rule_type in ('body', 'uri'):
                body_points += rule.score
            elif rule.rule_type == 'meta' and 'net' not in tflags:
                header_points += rule.score
                body_points += rule.score
            if "learn" in tflags:
                learn_points += rule.score
                continue
            autolearn_forced = autolearn_forced or "autolearn_force" in tflags
            points += rule.score
        self.ctxt.log.debug(
            "autolearn_points: %s, "
            "header_poins: %s, "
            "body_points: %s, "
            "learned_points: %s, "
            "autolearn_forced: %s, "
            "ham_threshold: %s, "
            "spam_threshold: %s",
            points, header_points, body_points, learn_points, autolearn_forced,
            self['bayes_auto_learn_threshold_spam'],
            self['bayes_auto_learn_threshold_nonspam']
        )
        self.set_local(msg, "autolearn_points", points)
        self.set_local(msg, "header_points", header_points)
        self.set_local(msg, "body_points", body_points)
        self.set_local(msg, "learned_points", learn_points)
        self.set_local(msg, "autolearn_forced", autolearn_forced)
        self.set_local(msg, "learner_thinks_spam",
                       points >= self['bayes_auto_learn_threshold_spam'])
        self.set_local(msg, "learner_thinks_ham",
                       points < self['bayes_auto_learn_threshold_nonspam'])
        self.set_local(msg, 'autolearn_forced', autolearn_forced)
        if autolearn_forced:
            self.set_local(msg, 'min_body_points',
                           MIN_BODY_POINTS_LOW_THRESHOLD)
            self.set_local(msg, 'min_header_points',
                           MIN_HEADER_POINTS_LOW_THRESHOLD)
        else:
            self.set_local(msg, 'min_body_points', MIN_BODY_POINTS)
            self.set_local(msg, 'min_header_points', MIN_HEADER_POINTS)

    def auto_learn_discriminator(self, ruleset, msg):
        """Decides if a message should be submitted for autolearning
        and submits it
        """
        bayes = self.ctxt.plugins.get("BayesPlugin", None)
        self.prepare_learning_metadata(msg, tests=ruleset.checked)
        if self.should_learn(msg) and bayes is not None:
            if self.get_local(msg, "learner_thinks_spam"):
                bayes.plugin_report(msg)
            elif self.get_local(msg, "learner_thinks_spam"):
                bayes.plugin_revoke(msg)
