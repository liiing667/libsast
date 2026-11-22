#!/usr/bin/env python
# -*- coding: utf_8 -*-
from datetime import datetime

from .core_matcher.pattern_matcher import PatternMatcher
from .core_matcher.choice_matcher import ChoiceMatcher
from .core_sgrep.semantic_sgrep import SemanticGrep
from .core_treesitter.ts_matcher import TreeSitterMatcher
from .rulepack import (
    RulePack,
    RulePackStore,
    RuleSet,
    default_store,
    get_rulepack,
    rulepack_from_rules,
)
from .scanner import Scanner


year = str(datetime.now().year)
__title__ = 'libsast'
__authors__ = 'Ajin Abraham'
__copyright__ = f'Copyright {year} Ajin Abraham, opensecurity.in'
__version__ = '3.2.0'
__version_info__ = tuple(int(i) for i in __version__.split('.'))
__all__ = [
    'Scanner',
    'ChoiceMatcher',
    'PatternMatcher',
    'SemanticGrep',
    'TreeSitterMatcher',
    'RulePack',
    'RuleSet',
    'RulePackStore',
    'default_store',
    'get_rulepack',
    'rulepack_from_rules',
    '__title__',
    '__authors__',
    '__copyright__',
    '__version__',
    '__version_info__',
]
