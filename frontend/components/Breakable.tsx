import { Fragment } from "react";

// Rule IDs like ENGINE_OFFICE_EXTERNAL_ON_OPEN in narrow columns: allow a line break only after
// "_" or ", " (<wbr>), never inside a word, and keep the copied text exact.
export default function Breakable({ text }: { text: string }) {
  return (
    <>
      {text.split(/(?<=_|, )/).map((part, i) => (
        <Fragment key={i}>{i > 0 && <wbr />}{part}</Fragment>
      ))}
    </>
  );
}
