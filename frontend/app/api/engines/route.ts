import { relayHealth } from "@/lib/api";

// Same-origin engine list for the Lab page (see ENGINES_ROUTE in lib/api.ts). Never cached.
export const dynamic = "force-dynamic";

export function GET() {
  return relayHealth();
}
