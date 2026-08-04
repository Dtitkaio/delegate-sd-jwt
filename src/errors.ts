/** Single error type raised by every code path in this library. */
export class DelegateSdJwtError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'DelegateSdJwtError';
  }
}

/** Wrap an unknown thrown value in a `DelegateSdJwtError` with added context. */
export function contextualize(context: string, cause: unknown): DelegateSdJwtError {
  const message = cause instanceof Error ? cause.message : String(cause);
  return new DelegateSdJwtError(`${context}: ${message}`, { cause });
}
