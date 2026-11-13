import { test } from "node:test";
import assert from "node:assert/strict";
import { VALIDATION_FILES, VALIDATION_GROUPS, directDownloadUrl, pinnedSourceUrl, hostedValidationCandidate } from "./additionalValidationCatalog.ts";

test("the supplemental catalog has 32 distinct, categorized files", () => {
  assert.equal(VALIDATION_FILES.length, 32);
  assert.equal(new Set(VALIDATION_FILES.map(f => f.id)).size, VALIDATION_FILES.length);
  assert.equal(new Set(VALIDATION_FILES.map(f => f.repository + ":" + (f.path || f.filename))).size, VALIDATION_FILES.length);
  assert.deepEqual(VALIDATION_GROUPS.map(g => VALIDATION_FILES.filter(f => f.group === g).length), [12, 7, 9, 2, 2]);
});

test("every GitHub link is a pinned direct binary download with a matching source reference", () => {
  for (const file of VALIDATION_FILES.filter(f => f.repository !== "Official EICAR")) {
    assert.match(file.revision, /^[a-f0-9]{40}$/);
    assert.ok(file.path && file.filename === file.path.split("/").at(-1));
    const download = new URL(directDownloadUrl(file));
    const source = new URL(pinnedSourceUrl(file));
    assert.equal(download.hostname, "raw.githubusercontent.com");
    assert.equal(source.hostname, "github.com");
    assert.ok(download.pathname.includes("/" + file.revision + "/"));
    assert.ok(source.pathname.includes("/blob/" + file.revision + "/"));
  }
});

test("spaces in PDF corpus filenames are URL-encoded and official AV controls remain offline-only", () => {
  const vera = VALIDATION_FILES.find(f => f.repository === "veraPDF/veraPDF-corpus");
  assert.ok(vera);
  assert.ok(directDownloadUrl(vera).includes("6.8%20Embedded%20files"));
  assert.ok(directDownloadUrl(vera).includes("veraPDF%20test%20suite"));
  for (const file of VALIDATION_FILES.filter(f => f.repository === "Official EICAR")) {
    assert.equal(file.handling, "offline-only");
    assert.equal(new URL(directDownloadUrl(file)).protocol, "https:");
    assert.equal(new URL(pinnedSourceUrl(file)).hostname, "www.eicar.org");
  }
});

test("known malformed PDFs and encrypted files are designated for local isolated testing", () => {
  const risky = ["bad-data.pdf", "bad-xref.pdf", "bad-direct-root.pdf", "append-xref-loop.pdf", "V4-aes.pdf"];
  for (const name of risky) {
    assert.equal(VALIDATION_FILES.find(f => f.filename === name)?.handling, "offline-only");
  }
});


test("inline hosted scanner accepts only unique allowed external benign-candidate cases", () => {
  assert.equal(hostedValidationCandidate("SampleDoc.docx")?.id, "validation-01");
  assert.equal(hostedValidationCandidate("sampledoc.DOCX")?.id, "validation-01");
  assert.equal(hostedValidationCandidate("SampleShow.pptx")?.filename, "SampleShow.pptx");
  for (const file of VALIDATION_FILES.filter(f => f.handling === "offline-only")) {
    assert.equal(hostedValidationCandidate(file.filename), null, file.filename);
  }
  assert.equal(hostedValidationCandidate("unlisted.exe"), null);
  assert.equal(hostedValidationCandidate("../SampleDoc.docx"), null);
});
