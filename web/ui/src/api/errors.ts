import { Code, ConnectError } from "@connectrpc/connect";

export { Code, ConnectError };

export function connectCode(err: unknown): Code | undefined {
  if (err instanceof ConnectError) return err.code;
  return undefined;
}

export function isCode(err: unknown, code: Code): boolean {
  return connectCode(err) === code;
}

/** Human readable message of an error, without the "[code]" prefix. */
export function errorMessage(err: unknown): string {
  if (err instanceof ConnectError) {
    const msg = err.rawMessage || Code[err.code] || "request failed";
    if (err.code === Code.Unavailable && /fetch|network/i.test(msg)) {
      return "The controller is not reachable.";
    }
    return msg;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

/** Whether a failed write was rejected because the branch moved. */
export function isConflict(err: unknown): boolean {
  return isCode(err, Code.FailedPrecondition) && /branch moved|base commit/i.test(errorMessage(err));
}

export function isNoChanges(err: unknown): boolean {
  return isCode(err, Code.FailedPrecondition) && /no changes/i.test(errorMessage(err));
}

export function codeName(err: unknown): string {
  const c = connectCode(err);
  return c === undefined ? "" : Code[c];
}
