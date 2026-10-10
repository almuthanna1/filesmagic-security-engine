import type { TestCase } from "./testCatalog";

// Test-only data generators: intentionally contain NO malware, scripts with
// executable bodies, downloadable payloads, or command execution targets.
// Do not open active-content fixtures in document viewers; upload directly to the scanner.
const utf8 = (s: string) => Buffer.from(s, "utf8");

function pdf(kind: "plain" | "javascript" | "launch" | "attachment"): Buffer {
  const stream = "BT /F1 15 Tf 50 730 Td (FilesMagic synthetic test) Tj ET\n";
  let extraCatalog = "";
  let extraObjects: string[] = [];
  if (kind === "javascript") {
    extraCatalog = " /OpenAction 6 0 R";
    extraObjects = ["<< /S /JavaScript /JS () >>"];
  }
  if (kind === "launch") {
    extraCatalog = " /OpenAction 6 0 R";
    extraObjects = ["<< /S /Launch >>"]; // Deliberately NO /F or /Win target
  }
  if (kind === "attachment") {
    extraCatalog = " /Names << /EmbeddedFiles << /Names [(note.txt) 6 0 R] >> >>";
    const attachment = "Harmless FilesMagic scanner fixture.\n";
    extraObjects = [
      "<< /Type /Filespec /F (note.txt) /EF << /F 7 0 R >> >>",
      "<< /Type /EmbeddedFile /Length " + Buffer.byteLength(attachment) + " >>\nstream\n" + attachment + "endstream",
    ];
  }
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R" + extraCatalog + " >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
    "<< /Length " + Buffer.byteLength(stream) + " >>\nstream\n" + stream + "endstream",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ...extraObjects,
  ];
  let output = "%PDF-1.4\n%Synthetic FilesMagic fixture\n";
  const offsets = [0];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(Buffer.byteLength(output));
    output += (i + 1) + " 0 obj\n" + objects[i] + "\nendobj\n";
  }
  const xref = Buffer.byteLength(output);
  output += "xref\n0 " + (objects.length + 1) + "\n0000000000 65535 f \n";
  for (const off of offsets.slice(1)) output += String(off).padStart(10, "0") + " 00000 n \n";
  output += "trailer\n<< /Size " + (objects.length + 1) + " /Root 1 0 R >>\nstartxref\n" + xref + "\n%%EOF\n";
  return utf8(output);
}

// Minimal, standards-structured, STORE-method ZIP writer for synthetic OOXML.
function crc32(data: Buffer): number {
  let value = 0xffffffff;
  for (const byte of data) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
}
function zip(entries: [string, string][]): Buffer {
  const local: Buffer[] = [], central: Buffer[] = [];
  let offset = 0;
  for (const [filename, text] of entries) {
    const name = utf8(filename), data = utf8(text), crc = crc32(data);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(data.length, 18);
    head.writeUInt32LE(data.length, 22);
    head.writeUInt16LE(name.length, 26);
    local.push(head, name, data);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt32LE(crc, 16);
    c.writeUInt32LE(data.length, 20);
    c.writeUInt32LE(data.length, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(offset, 42);
    central.push(c, name);
    offset += head.length + name.length + data.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, cd, end]);
}
function docx(kind: "plain" | "autoload" | "protocol"): Buffer {
  const ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
  const entries: [string, string][] = [
    ["[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'],
    ["_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'],
    ["word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="' + ns + '"><w:body><w:p><w:r><w:t>FilesMagic synthetic test fixture</w:t></w:r></w:p><w:sectPr/></w:body></w:document>'],
  ];
  if (kind !== "plain") {
    const target = kind === "autoload" ? "https://example.invalid/synthetic-template.dotx" : "ms-test-fixture:inert";
    const type = kind === "autoload" ? "attachedTemplate" : "hyperlink";
    entries.push(["word/_rels/document.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/' + type + '" Target="' + target + '" TargetMode="External"/></Relationships>']);
  }
  return zip(entries);
}
export function makeTestFile(t: TestCase): Buffer {
  switch (t.id) {
    case "benign-txt": return utf8("FilesMagic benign plain text control.\n");
    case "benign-csv": return utf8("item,quantity\napples,3\nbread,1\n");
    case "benign-svg": return utf8('<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80"><rect width="80" height="80" fill="blue"/></svg>\n');
    case "benign-pdf": return pdf("plain");
    case "benign-docx": return docx("plain");
    case "benign-rtf": return utf8(String.raw`{\rtf1\ansi FilesMagic benign rich text control.}`);
    case "svg-script": return utf8('<svg xmlns="http://www.w3.org/2000/svg"><script></script></svg>\n');
    case "svg-event": return utf8('<svg xmlns="http://www.w3.org/2000/svg" onload=""><rect width="10" height="10"/></svg>\n');
    case "pdf-js": return pdf("javascript");
    case "pdf-attachment": return pdf("attachment");
    case "docx-autoload": return docx("autoload");
    case "rtf-dde": return utf8(String.raw`{\rtf1\ansi DDEAUTO synthetic marker only; no application or command.}`);
    case "pdf-launch": return pdf("launch");
    case "docx-protocol": return docx("protocol");
    case "rtf-object": return utf8(String.raw`{\rtf1\ansi Synthetic object-update marker {\object\objupdate} no executable payload.}`);
    case "invalid-pdf": return utf8("%PDF-1.4\nThis file is deliberately not a valid PDF.\n");
    default: throw new Error("Unknown test fixture");
  }
}
