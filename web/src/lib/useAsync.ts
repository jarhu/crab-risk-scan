import { useCallback, useEffect, useRef, useState } from "react";

export interface AsyncState<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  reload: () => void;
  setData: (value: T) => void;
}

/** Run an async loader whenever its dependencies change; stale responses are discarded. */
export function useAsync<T>(loader: () => Promise<T>, deps: readonly unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const generation = useRef(0);

  useEffect(() => {
    const current = ++generation.current;
    setLoading(true);
    loader().then(
      (value) => {
        if (current !== generation.current) return;
        setData(value);
        setError(null);
        setLoading(false);
      },
      (reason: unknown) => {
        if (current !== generation.current) return;
        setError(reason);
        setLoading(false);
      },
    );
    // The caller supplies the dependency list for the loader.
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((value) => value + 1), []);
  return { data, error, loading, reload, setData };
}

/** Call `callback` every `ms` milliseconds while `active` is true and the page is visible. */
export function useInterval(callback: () => void, ms: number, active: boolean): void {
  const saved = useRef(callback);
  saved.current = callback;
  useEffect(() => {
    if (!active) return undefined;
    const id = setInterval(() => {
      if (typeof document === "undefined" || document.visibilityState !== "hidden") saved.current();
    }, ms);
    return () => clearInterval(id);
  }, [ms, active]);
}
