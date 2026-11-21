import { SEVERITIES, type JobInput, type JobOptions, type JobSource } from "../api/types";

export interface JobValues {
  type: "path" | "git";
  path: string;
  url: string;
  ref: string;
  engines: string;
  sbom: boolean;
  failOn: string;
}

export const EMPTY_JOB: JobValues = { type: "path", path: "", url: "", ref: "", engines: "auto", sbom: false, failOn: "" };

export function jobValuesFrom(source: JobSource, options: JobOptions): JobValues {
  return {
    type: source.type,
    path: source.type === "path" ? source.path : "",
    url: source.type === "git" ? source.url : "",
    ref: source.type === "git" ? (source.ref ?? "") : "",
    engines: options.engines ?? "auto",
    sbom: options.sbom ?? false,
    failOn: options.fail_on ?? "",
  };
}

export function jobInputFrom(values: JobValues): JobInput {
  const source: JobSource =
    values.type === "path" ? { type: "path", path: values.path.trim() } : { type: "git", url: values.url.trim(), ...(values.ref.trim() ? { ref: values.ref.trim() } : {}) };
  const options: JobOptions = { engines: values.engines.trim() || "auto", sbom: values.sbom };
  if (values.failOn) options.fail_on = values.failOn;
  return { source, options };
}

export function JobFields({ values, onChange }: { values: JobValues; onChange: (values: JobValues) => void }) {
  const set = <K extends keyof JobValues>(key: K, value: JobValues[K]) => onChange({ ...values, [key]: value });
  return (
    <>
      <fieldset className="field radio-group">
        <legend>Source</legend>
        <label>
          <input type="radio" name="source-type" checked={values.type === "path"} onChange={() => set("type", "path")} /> Server path
        </label>
        <label>
          <input type="radio" name="source-type" checked={values.type === "git"} onChange={() => set("type", "git")} /> Git repository
        </label>
      </fieldset>
      {values.type === "path" ? (
        <label className="field wide">
          <span>Path inside the project's scan path (administrators: any allowed scan root)</span>
          <input required maxLength={4096} value={values.path} onChange={(e) => set("path", e.target.value)} />
        </label>
      ) : (
        <>
          <label className="field wide">
            <span>Repository URL</span>
            <input required type="url" placeholder="https://" maxLength={2048} value={values.url} onChange={(e) => set("url", e.target.value)} />
          </label>
          <label className="field">
            <span>Ref (optional)</span>
            <input maxLength={255} value={values.ref} onChange={(e) => set("ref", e.target.value)} />
          </label>
        </>
      )}
      <label className="field">
        <span>Engines</span>
        <input list="engine-choices" maxLength={200} value={values.engines} onChange={(e) => set("engines", e.target.value)} />
        <datalist id="engine-choices">
          <option value="auto" />
          <option value="all" />
          <option value="none" />
        </datalist>
      </label>
      <label className="field">
        <span>Fail on</span>
        <select value={values.failOn} onChange={(e) => set("failOn", e.target.value)}>
          <option value="">Project policy default</option>
          {SEVERITIES.map((level) => (
            <option key={level} value={level}>
              {level}
            </option>
          ))}
          <option value="none">none</option>
        </select>
      </label>
      <label className="field checkbox">
        <input type="checkbox" checked={values.sbom} onChange={(e) => set("sbom", e.target.checked)} /> Generate SBOM
      </label>
    </>
  );
}
