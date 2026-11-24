"use client";

export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <section className="state-card error" role="alert" aria-labelledby="page-error-title">
    <h1 id="page-error-title">This view could not be loaded</h1>
    <p>Try loading the page again. No action request will be resubmitted.</p>
    {error.digest && <small>Reference: {error.digest}</small>}
    <p><button className="button secondary" onClick={reset}>Try again</button></p>
  </section>;
}
