import { useEffect, useState } from "react";

/** Hash routing keeps every view and selection linkable without a server rewrite rule. */
export function useRoute(): string[] {
  const read = () => window.location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  const [parts, setParts] = useState<string[]>(read);
  useEffect(() => {
    const onChange = () => setParts(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return parts;
}

export function go(...parts: string[]): void {
  window.location.hash = "/" + parts.map(encodeURIComponent).join("/");
}
