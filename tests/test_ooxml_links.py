"""OOXML activation graph on inert packages (every external target is an RFC 2606 .invalid host)."""

import pytest

from app import engine, worker
from app.engine import ooxml_links as links
from app.engine.ooxml_links import (
    CLICK, DISPLAYED, IMAGE, NOT_ACTIVATED, ON_ACTION, ON_OPEN, UNDETERMINED, Reference, classify, references,
)
from app.scanners import SCANNERS
from app.scanners.custom.errors import CustomScanError
from evaluation.cases import INERT_OLE, cases, verdicts
from tests import custom_fixtures as fx

REL, URL = fx.REL, "https://example.invalid/x"
CASE = {c["id"]: c["data"] for c in cases()}
NS = f'xmlns:r="{REL}" xmlns:o="{fx.VML_OFFICE}"'


def states(data: bytes) -> list[tuple[str, str]]:
    return [(a.relationship.id, a.state) for a in links.scan(data).activations]


def external(rid: str, rel_type: str = "image") -> tuple:
    return (rid, f"{REL}/{rel_type}", URL, "External")


# ----------------------------------------------------------------------------- what an element means

@pytest.mark.parametrize("element, attrs, auto, state", [
    ("attachedTemplate", {}, False, ON_OPEN),
    ("sourceFileName", {}, False, ON_OPEN),
    ("blip", {}, False, IMAGE),
    ("imagedata", {}, False, IMAGE),
    ("OLEObject", {"Type": "Link", "UpdateMode": "Always"}, False, ON_OPEN),
    ("OLEObject", {"Type": "Link", "UpdateMode": "OnCall"}, False, ON_ACTION),
    ("oleObject", {"oleUpdate": "OLEUPDATE_ALWAYS"}, False, ON_OPEN),  # Excel
    ("oleObject", {"oleUpdate": "OLEUPDATE_ONCALL"}, False, ON_ACTION),
    ("oleObj", {}, True, ON_OPEN),  # PowerPoint with <p:link updateAutomatic="1"/>
    ("oleObj", {}, False, ON_ACTION),
    ("subDoc", {}, False, ON_ACTION),
    ("hyperlink", {}, False, CLICK),
    ("hlinkClick", {}, False, CLICK),
    ("somethingNew", {}, False, UNDETERMINED),
])
def test_what_the_referencing_element_says_about_an_external_target(element, attrs, auto, state):
    assert classify(Reference(element, "id", attrs, auto), external=True)[0] == state


@pytest.mark.parametrize("element, state", [("OLEObject", DISPLAYED), ("oleObj", DISPLAYED), ("control", DISPLAYED),
                                            ("somethingNew", UNDETERMINED)])
def test_what_the_referencing_element_says_about_an_embedded_object(element, state):
    assert classify(Reference(element, "id", {}), external=False)[0] == state


def test_references_are_read_from_relationship_attributes_and_vml_relid():
    xml = (f'<root {NS} xmlns:p="urn:p"><a r:link="rId1"/><v o:relid="rId2"/><b id="rId3"/>'
           f'<p:oleObj r:id="rId4"><p:link updateAutomatic="1"/></p:oleObj></root>').encode()
    refs = references(xml)
    assert sorted(refs) == ["rId1", "rId2", "rId4"]  # a plain "id" attribute names no relationship
    assert refs["rId4"][0].auto_update is True


# ----------------------------------------------------------------------------- packages

def test_a_template_is_on_open_only_when_settings_references_it():
    assert states(CASE["6c-docx-template-referenced-by-settings"]) == [("rId1", ON_OPEN)]
    assert states(CASE["6b-docx-external-template"]) == [("rId9", NOT_ACTIVATED)]


def test_the_activation_chain_names_every_step():
    chain = links.scan(CASE["6c-docx-template-referenced-by-settings"]).activations[0].chain
    assert chain == ("package -> word/document.xml (officedocument) -> word/settings.xml (settings) -> "
                     "attachedTemplate id='rId1' -> attachedtemplate https://template.example.invalid/normal.dotm")


def test_linked_pictures_and_vml_images_load_on_open():
    vml = fx.linked_docx(body='<w:p><w:r><w:pict><v:imagedata r:id="rId9"/></w:pict></w:r></w:p>',
                         main_rels=(external("rId9"),))
    assert states(CASE["6d-docx-linked-picture"]) == states(vml) == [("rId9", IMAGE)]


def test_an_auto_updating_ole_link_loads_on_open_and_an_on_call_one_on_action():
    def ole(mode):
        body = f'<w:p><w:r><w:object><o:OLEObject Type="Link" UpdateMode="{mode}" r:id="rId9"/></w:object></w:r></w:p>'
        return fx.linked_docx(body=body, main_rels=(external("rId9", "oleObject"),))
    assert states(ole("Always")) == [("rId9", ON_OPEN)] and states(ole("OnCall")) == [("rId9", ON_ACTION)]


def test_embedded_objects_are_displayed_or_merely_present():
    assert states(CASE["6e-docx-embedded-object-displayed"]) == [("rId10", DISPLAYED)]
    assert states(CASE["6f-docx-embedded-object-not-displayed"]) == [("rId10", NOT_ACTIVATED)]
    orphan = fx.linked_docx(parts={"word/embeddings/oleObject1.bin": INERT_OLE})
    assert links.scan(orphan).unrelated_objects == ["word/embeddings/oleObject1.bin"]


def test_relationships_of_a_part_office_never_loads_are_not_activated():
    data = fx.linked_docx(parts={"word/orphan.xml": f'<x {NS}><y r:id="rId9"/></x>',
                                 "word/_rels/orphan.xml.rels": fx.rels_xml(external("rId9", "attachedTemplate"))})
    activation = links.scan(data).activations[0]
    assert activation.state == NOT_ACTIVATED and "never loaded" in activation.why


@pytest.mark.parametrize("data, why", [
    (fx.linked_docx(main_rels=(("rId10", f"{REL}/oleObject", "embeddings/oleObject1.bin"),),
                    body='<w:p><w:r><w:object><o:OLEObject Type="Embed" r:id="rId10"/></w:object></w:r></w:p>',
                    parts={"word/embeddings/oleObject1.bin": INERT_OLE,
                           "word/embeddings/_rels/oleObject1.bin.rels": fx.rels_xml(external("rId1", "oleObject"))}),
     "is not XML"),
    (fx.linked_docx(body="<w:p>", main_rels=(external("rId9"),)), "is not well-formed XML"),
    (fx.linked_docx(body='<w:p><w:r><w:drawing><a:blip r:link="rId9"/></w:drawing></w:r></w:p>',
                    main_rels=(external("rId9"), ("rId9", f"{REL}/image", "https://other.invalid/y", "External"))),
     "declared more than once"),
])
def test_unknowable_activation_is_undetermined(data, why):
    undetermined = [a for a in links.scan(data).activations if a.state == UNDETERMINED]
    assert undetermined and why in undetermined[0].why


def test_a_package_whose_relationships_cannot_be_read_fails_closed():
    files = fx.office_parts("docx")
    files["word/_rels/document.xml.rels"] = "<Relationships><broken"
    with pytest.raises(CustomScanError):
        links.scan(fx.zip_parts(files))


def test_not_a_package_is_not_applicable():
    assert links.scan(b"%PDF-1.7") is None


# ----------------------------------------------------------------------------- unified engine

SEVERITY = ["SAFE", "SUSPICIOUS", "MALICIOUS"]


@pytest.mark.parametrize("case", sorted(CASE))
def test_the_unified_verdict_is_never_lower_than_the_reference_verdict(case):
    reference = verdicts(worker.analyse(SCANNERS, CASE[case]))["aggregate"]
    unified = verdicts(engine.correlate(worker.analyse(engine.SCANNERS, CASE[case])))["aggregate"]
    assert reference == unified or (reference in SEVERITY and SEVERITY.index(unified) > SEVERITY.index(reference)) \
        or (reference, unified) == ("MALICIOUS", "SUSPICIOUS") and case.startswith("5a")  # the PDF correction


def test_a_linked_picture_raises_the_verdict_and_reference_findings_stay():
    unified = engine.correlate(worker.analyse(engine.SCANNERS, CASE["6d-docx-linked-picture"]))
    rules = {f.rule_id for f in unified.findings}
    assert {"OFFICE_EXTERNAL_RESOURCE", "ENGINE_OFFICE_LINKED_PICTURE_LOADS_ON_OPEN"} <= rules
    assert verdicts(unified)["aggregate"] == "SUSPICIOUS"


@pytest.mark.parametrize("case, note", [
    ("6b-docx-external-template", "kept although no part Office loads references it"),
    ("6c-docx-template-referenced-by-settings", "confirmed: a part Office loads references an external target"),
    ("6e-docx-embedded-object-displayed", "shown in the document and runs only when activated"),
    ("6f-docx-embedded-object-not-displayed", "no element shows the object"),
])
def test_reference_office_findings_are_qualified_not_removed(case, note):
    reference = {f.rule_id for f in worker.analyse(SCANNERS, CASE[case]).findings}
    unified = engine.correlate(worker.analyse(engine.SCANNERS, CASE[case]))
    assert reference <= {f.rule_id for f in unified.findings}
    assert note in next(f.description for f in unified.findings if f.rule_id == "ENGINE_CORRELATION")
