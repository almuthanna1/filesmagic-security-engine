import { test } from "node:test";
import assert from "node:assert/strict";
import { VALIDATION_FILES, VALIDATION_GROUPS, directDownloadUrl, pinnedSourceUrl, hostedValidationCandidate, matchesPinnedValidationHash } from "./additionalValidationCatalog.ts";

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

test("qpdf encrypted and malformed fixtures use pinned hashes in hosted regression tests", () => {
  const risky = ["bad-data.pdf", "bad-xref.pdf", "bad-direct-root.pdf", "append-xref-loop.pdf", "V4-aes.pdf"];
  const hashes = [
    "919998d65cecd40f1c33cf56853a517acc0e18f438fcc098f4c17a086c875057",
    "5895dfedf978f600b12e29643617dbb111869b60526d957878e349571e1467d1",
    "0d7549c02c38717627deb10d1155c1b513d35036208e77d687597c77d04dc3b4",
    "7c67daccc433f574fbaf815d0d376cc79f40f95082ef1b231af436e9f7d27091",
    "1d8a812844b8d8c7ba085a627eb3b7ab52aa651c6143ca07315084220a113240",
  ];
  for (const [i, name] of risky.entries()) {
    const file = VALIDATION_FILES.find(f => f.filename === name);
    assert.ok(file);
    assert.equal(file.handling, "hosted-regression", name);
    assert.equal(file.expectedSha256, hashes[i], name);
    assert.equal(hostedValidationCandidate(name)?.id, file.id);
    assert.equal(matchesPinnedValidationHash(file, hashes[i]), true);
    assert.equal(matchesPinnedValidationHash(file, "0".repeat(64)), false);
    assert.equal(matchesPinnedValidationHash(file, "not a sha256"), false);
  }
});


test("inline hosted scanner accepts only unique allowed external benign-candidate cases", () => {
  assert.equal(hostedValidationCandidate("SampleDoc.docx")?.id, "validation-01");
  assert.equal(hostedValidationCandidate("sampledoc.DOCX")?.id, "validation-01");
  assert.equal(hostedValidationCandidate("SampleShow.pptx")?.filename, "SampleShow.pptx");
  assert.equal(hostedValidationCandidate("V4-aes.pdf")?.handling, "hosted-regression");
  assert.equal(hostedValidationCandidate("bad-xref.pdf")?.handling, "hosted-regression");
  for (const file of VALIDATION_FILES.filter(f => f.handling === "offline-only")) {
    assert.equal(hostedValidationCandidate(file.filename), null, file.filename);
  }
  assert.equal(hostedValidationCandidate("unlisted.exe"), null);
  assert.equal(hostedValidationCandidate("harmless-clean.docm"), null);
  assert.equal(hostedValidationCandidate("eicar.com.txt"), null);
  assert.equal(hostedValidationCandidate("eicar.com.zip"), null);
  assert.equal(hostedValidationCandidate("../SampleDoc.docx"), null);
});
