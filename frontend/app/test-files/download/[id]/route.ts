import { CASE_BY_ID } from "@/lib/testCatalog";
import { makeTestFile } from "@/lib/testFixtureBuilders";

export const runtime = "nodejs";

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> }
) {
  const { id } = await context.params;
  const selected = Object.hasOwn(CASE_BY_ID, id) ? CASE_BY_ID[id] : undefined;
  if (!selected) return new Response("Test file not found", { status: 404 });
  const contents = makeTestFile(selected);
  return new Response(Uint8Array.from(contents), {
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": 'attachment; filename="' + selected.filename + '"',
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
