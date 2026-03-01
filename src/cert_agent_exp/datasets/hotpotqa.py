"""HotpotQA: iter_documents for corpus build, iter_tasks for task instances. Frozen delimiter."""

from typing import Any, Iterator

# Frozen: paragraph delimiter "\n\n", within paragraph " " (single space).
PARAGRAPH_DELIM = "\n\n"
WITHIN_PARAGRAPH_DELIM = " "


def iter_documents(raw_rows: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Yield one doc per row for corpus build. Text joined with frozen delimiters."""
    for row in raw_rows:
        context = row.get("context", {})
        if isinstance(context, dict):
            titles = context.get("title", [])
            sentences = context.get("sentences", [])
            parts = []
            for title, sents in zip(titles, sentences):
                flat = WITHIN_PARAGRAPH_DELIM.join(
                    s for sent in sents for s in (sent if isinstance(sent, list) else [sent])
                )
                parts.append(f"**{title}**\n" + flat)
            context_str = PARAGRAPH_DELIM.join(parts)
        elif isinstance(context, list) and context and isinstance(context[0], (list, tuple)):
            parts = []
            for (title, sents) in context:
                parts.append(f"**{title}**\n" + WITHIN_PARAGRAPH_DELIM.join(sents))
            context_str = PARAGRAPH_DELIM.join(parts)
        else:
            context_str = PARAGRAPH_DELIM.join(context) if isinstance(context, list) else str(context)
        yield {
            "id": row.get("id", ""),
            "question": row.get("question", ""),
            "context": context_str,
            "answer": row.get("answer", ""),
            "type": "hotpotqa",
        }


def iter_tasks(raw_rows: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Yield task instances: question, answer, supporting_facts, context_titles, context_paragraphs."""
    for row in raw_rows:
        context = row.get("context", {})
        if isinstance(context, dict):
            titles = context.get("title", [])
            sentences = context.get("sentences", [])
            context_titles = list(titles)
            context_paragraphs = []
            for sents in sentences:
                flat = WITHIN_PARAGRAPH_DELIM.join(
                    s for sent in sents for s in (sent if isinstance(sent, list) else [sent])
                )
                context_paragraphs.append(flat)
        else:
            context_titles = []
            context_paragraphs = []
        supporting_facts = row.get("supporting_facts", {})
        if isinstance(supporting_facts, dict):
            sf = {"title": list(supporting_facts.get("title", [])), "sent_id": list(supporting_facts.get("sent_id", []))}
        else:
            sf = {}
        yield {
            "id": row.get("id", ""),
            "question": row.get("question", ""),
            "answer": row.get("answer", ""),
            "supporting_facts": sf,
            "context_titles": context_titles,
            "context_paragraphs": context_paragraphs,
            "type": "hotpotqa",
        }
