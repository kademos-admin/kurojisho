"""tree-sitter front end. Grammars ship inside their wheels; nothing is fetched at runtime."""

from __future__ import annotations

from collections.abc import Callable
from functools import cache

import tree_sitter_go
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Parser

from kurojisho.ingest.code.extract import Extractor, FileFacts
from kurojisho.ingest.code.languages.go import GoExtractor
from kurojisho.ingest.code.languages.java import JavaExtractor
from kurojisho.ingest.code.languages.javascript import JavaScriptExtractor
from kurojisho.ingest.code.languages.python import PythonExtractor

#: Bump whenever extraction output changes, so cached facts are discarded.
EXTRACTOR_VERSION = "2"

#: Source files larger than this are recorded but not parsed (noted on the File node).
MAX_SOURCE_BYTES = 2 * 1024 * 1024

_GRAMMARS: dict[str, Callable[[], object]] = {
    "python": tree_sitter_python.language,
    "javascript": tree_sitter_javascript.language,
    "typescript": tree_sitter_typescript.language_typescript,
    "tsx": tree_sitter_typescript.language_tsx,
    "go": tree_sitter_go.language,
    "java": tree_sitter_java.language,
}

_EXTRACTORS: dict[str, type[Extractor]] = {
    "python": PythonExtractor,
    "javascript": JavaScriptExtractor,
    "typescript": JavaScriptExtractor,
    "tsx": JavaScriptExtractor,
    "go": GoExtractor,
    "java": JavaExtractor,
}

SUPPORTED_LANGUAGES = frozenset(_GRAMMARS)


@cache
def _parser(lang: str) -> Parser:
    return Parser(Language(_GRAMMARS[lang]()))


def extract(lang: str, source: bytes) -> FileFacts:
    """Parse ``source`` and return its facts. Syntax errors never raise: they are recorded."""
    tree = _parser(lang).parse(source)
    extractor = _EXTRACTORS[lang]()
    facts = extractor.run(tree.root_node)
    facts.lang = lang
    return facts
