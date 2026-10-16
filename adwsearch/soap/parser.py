# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Parse ADWS SOAP responses (decoded NBF records) into usable Python objects.

The decoded record stream is turned into a small element tree, then navigated. Covers the
WS-Enumeration PullResponse (EnumerationContext, EndOfSequence, Items) where each item is a
directory object whose child elements are attributes, each holding one or more <ad:value>.
"""

from dataclasses import dataclass, field

from adwsearch.soap import templates

from adwsearch.transport.nbf.records import (
    Attribute, EndElement, StartElement, Text, Xmlns,
)


@dataclass
class Node:
    prefix: str | None
    name: str
    attributes: list[tuple] = field(default_factory=list)   # (prefix, name, value)
    children: list["Node"] = field(default_factory=list)
    text: object | None = None
    namespaces: dict = field(default_factory=dict)

    @property
    def expanded_name(self):
        return self.namespaces.get(self.prefix or None), self.name


@dataclass
class AdObject:
    object_class: str                                       # local element name, e.g. "user"
    attributes: dict[str, list[object]] = field(default_factory=dict)


@dataclass
class PullResult:
    context: str | None
    end_of_sequence: bool
    items: list[AdObject]


class AdwsSoapFault(Exception):
    """SOAP 1.2 Fault returned by an ADWS endpoint.

    ``subcode`` carries the ``s:Code/s:Subcode/s:Value`` string (e.g.
    ``"wsa:ActionNotSupported"``), which is how :meth:`AdwsClient.get`
    decides whether a WS-Transfer failure means "endpoint doesn't speak
    Transfer, try the other / fall back to search" or "we built a
    malformed request" (which must not be silently hidden).
    """

    def __init__(self, code: str | None, subcode: str | None, reason: str | None,
                 *, ldap_result_code: int | None = None,
                 win32_error_code: int | None = None):
        self.code = code
        self.subcode = subcode
        self.reason = reason
        self.ldap_result_code = ldap_result_code
        self.win32_error_code = win32_error_code
        detail = subcode or code or "s:Fault"
        if reason:
            detail = f"{detail}: {reason}"
        super().__init__(detail)


def records_to_tree(events) -> Node:
    root = Node(None, "#root")
    stack = [root]
    for event in events:
        if isinstance(event, StartElement):
            node = Node(event.prefix, event.name, namespaces=dict(stack[-1].namespaces))
            stack[-1].children.append(node)
            stack.append(node)
        elif isinstance(event, Attribute):
            stack[-1].attributes.append((event.prefix, event.name, event.value))
        elif isinstance(event, Xmlns):
            stack[-1].namespaces[event.prefix or None] = event.value
        elif isinstance(event, Text):
            # ADWS splits long values across consecutive text records on the
            # wire (e.g. a 28-byte objectSid comes as Bytes8(27) + Bytes8(1)).
            # Concatenate same-type payloads; keep the first for mixed types
            # (very rare, defensive fallback).
            current = stack[-1].text
            if current is None:
                stack[-1].text = event.value
            elif isinstance(current, (bytes, bytearray)) and isinstance(event.value, (bytes, bytearray)):
                stack[-1].text = bytes(current) + bytes(event.value)
            elif isinstance(current, str) and isinstance(event.value, str):
                stack[-1].text = current + event.value
        elif isinstance(event, EndElement):
            stack.pop()
    return root.children[0] if len(root.children) == 1 else root


def _find(node: Node, name: str) -> Node | None:
    """Depth-first search for the first descendant (or self) with the given local name."""
    if node is None:
        return None
    stack = [node]
    while stack:
        current = stack.pop()
        if current.name == name:
            return current
        stack.extend(reversed(current.children))
    return None


def _clean(value):
    return value.strip() if isinstance(value, str) else value


def _parse_item(node: Node) -> AdObject:
    attributes: dict[str, list[object]] = {}
    for attr_node in node.children:
        # An `<ad:value/>` self-closed element carries no Text record: preserve
        # it as "" rather than silently dropping the value (AD stores real
        # empty-string attributes; skipping them would understate the answer).
        values = [_clean(v.text) if v.text is not None else ""
                  for v in attr_node.children if v.name == "value"]
        attributes[attr_node.name] = values
    return AdObject(object_class=node.name, attributes=attributes)


def parse_enumerate_response(events) -> str | None:
    """Return the EnumerationContext from a wsen:EnumerateResponse."""
    root = records_to_tree(events)
    fault = _parse_fault(root)
    if fault is not None:
        raise fault
    response = _find(root, "EnumerateResponse")
    if response is None:
        raise ValueError("response does not contain a wsen:EnumerateResponse element")
    context = _find(response, "EnumerationContext")
    return _clean(context.text) if context and context.text is not None else None


def parse_pull_response(events) -> PullResult:
    root = records_to_tree(events)
    fault = _parse_fault(root)
    if fault is not None:
        raise fault
    pull_response = _find(root, "PullResponse")
    if pull_response is None:
        raise ValueError("response does not contain a wsen:PullResponse element")

    context_node = _find(pull_response, "EnumerationContext")
    context = _clean(context_node.text) if context_node and context_node.text is not None else None
    end_of_sequence = _find(pull_response, "EndOfSequence") is not None

    items_node = _find(pull_response, "Items")
    items = [_parse_item(item) for item in items_node.children] if items_node else []
    return PullResult(context=context, end_of_sequence=end_of_sequence, items=items)


def _parse_fault(root: Node) -> AdwsSoapFault | None:
    """Extract a SOAP 1.2 Fault from ``root``, or return ``None`` if absent.

    Reads ``s:Code/s:Value``, ``s:Code/s:Subcode/s:Value`` (recursing one
    level, which is where ADWS places ``wsa:ActionNotSupported`` and
    friends) and ``s:Reason/s:Text``. All three are optional; the caller
    gets whatever the server actually sent.
    """
    fault = _find(root, "Fault")
    if fault is None:
        return None
    code_node = _find(fault, "Code")
    code = subcode = None
    if code_node is not None:
        for child in code_node.children:
            if child.name == "Value" and code is None:
                code = _clean(child.text) if isinstance(child.text, str) else None
            elif child.name == "Subcode":
                inner = _find(child, "Value")
                if inner is not None and isinstance(inner.text, str):
                    subcode = _clean(inner.text)
    reason_node = _find(fault, "Reason")
    reason = None
    if reason_node is not None:
        text_node = _find(reason_node, "Text")
        if text_node is not None and isinstance(text_node.text, str):
            reason = _clean(text_node.text)
    def error_number(name):
        node = _find(fault, name)
        if node is None or node.text is None:
            return None
        try:
            value = str(node.text).strip()
            return int(value, 16 if value.lower().startswith("0x") else 10)
        except (ValueError, TypeError):
            return None
    return AdwsSoapFault(code, subcode, reason,
                         ldap_result_code=error_number("ResultCode"),
                         win32_error_code=error_number("Win32ErrorCode"))


def parse_get_response(events) -> AdObject | None:
    """Return the AdObject from a wxf:GetResponse, or ``None`` if the body is empty.

    WS-Transfer's ``GetResponse`` wraps the resource representation directly:
    for ADWS this is a single ``addata:<class>`` element with the same shape
    as the items inside a PullResponse, so :func:`_parse_item` applies.

    If the envelope carries an ``s:Fault`` instead, raise
    :class:`AdwsSoapFault` with code/subcode/reason extracted so the caller
    can decide whether to retry or propagate.
    """
    root = records_to_tree(events)
    if root.expanded_name != (templates.NS_SOAP, 'Envelope'):
        raise ValueError('GetResponse requires a SOAP Envelope')
    def direct(node, namespace, name):
        matches = [child for child in node.children
                   if child.expanded_name == (namespace, name)]
        if len(matches) != 1:
            raise ValueError('GetResponse requires exactly one ' + name)
        return matches[0]
    body = direct(root, templates.NS_SOAP, 'Body')
    if any(child.expanded_name == (templates.NS_SOAP, 'Fault') for child in body.children):
        fault = _parse_fault(body)
        if fault is not None:
            raise fault
    header = direct(root, templates.NS_SOAP, 'Header')
    action = direct(header, templates.NS_WSA, 'Action')
    if action.text != templates.ACTION_GET + 'Response':
        raise ValueError('response does not have the WS-Transfer GetResponse action')
    if len(body.children) > 1:
        raise ValueError('GetResponse contains multiple representations')
    if not body.children:
        return None
    representation = body.children[0]
    if representation.expanded_name[0] != templates.NS_ADDATA:
        raise ValueError('GetResponse does not contain a directory representation')
    return _parse_item(representation)
