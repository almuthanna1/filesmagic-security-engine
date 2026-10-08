"use client";

import { useId, useState } from "react";
import styles from "./FileDropzone.module.css";

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

interface Props {
  file: File | null;
  disabled: boolean;
  onSelect: (file: File) => void;
}

export default function FileDropzone({ file, disabled, onSelect }: Props) {
  const inputId = useId();
  const [dragging, setDragging] = useState(false);

  return (
    <div
      className={`${styles.zone} ${dragging ? styles.dragging : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const dropped = e.dataTransfer.files[0];
        if (dropped && !disabled) onSelect(dropped);
      }}
    >
      <p className={styles.hint}>Drag and drop a file here, or</p>
      {/* Visually hidden but still keyboard-focusable; the label acts as the visible button. */}
      <input
        id={inputId}
        type="file"
        className={styles.input}
        disabled={disabled}
        onChange={(e) => {
          const picked = e.target.files?.[0];
          if (picked) onSelect(picked);
          e.target.value = ""; // allow re-selecting the same file
        }}
      />
      <label htmlFor={inputId} className={styles.label} aria-disabled={disabled}>
        Choose file
      </label>

      <dl className={styles.selected} aria-live="polite">
        {file ? (
          <>
            <div>
              <dt>Selected file</dt>
              <dd className={styles.filename}>{file.name}</dd>
            </div>
            <div>
              <dt>Size</dt>
              <dd>{formatBytes(file.size)}</dd>
            </div>
          </>
        ) : (
          <div>
            <dt>Selected file</dt>
            <dd className={styles.muted}>No file selected</dd>
          </div>
        )}
      </dl>
    </div>
  );
}
