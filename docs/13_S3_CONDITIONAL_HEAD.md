# S3-compatible conditional HEAD — experiment plan

- Created: **2026-10-31**
- Status: **optional future backend, not the product path.** The consumer app stores the vault in a local folder and does not call a cloud API. This note stays so an S3-compatible adapter can be added later. No network calls and no credentials.
- Earlier owner choice, now demoted: S3-compatible conditional writes (Cloudflare R2 or AWS S3) are a possible later backend, not the first shipping storage.

## What the code does now

`eidoron-provider-local` defines `ConditionalHead`:

- `IfNoneMatchStar` maps to HTTP `If-None-Match: *`. The write succeeds only when no HEAD is stored.
- `IfMatch(etag)` maps to HTTP `If-Match`. The write succeeds only when the stored etag is exactly that value.
- A failed precondition leaves the stored bytes unchanged and returns `PreconditionFailed`. The error text does not include the HEAD bytes.

`MemoryHead` is an in-process fake. Its etag is a generation counter. Writing the same bytes again still yields a new etag, so the etag is not a hash of the content. A real provider's etag is an opaque string. Do not treat it as plaintext equality.

No adapter connects to R2 or S3. No access key, endpoint URL, or account id belongs in this repository.

## What must be recorded before either provider is trusted

Run these against a disposable bucket, from a machine that already has credentials outside the repo. Keep the raw status codes and dates. Do not paste secrets or object bodies that are not synthetic.

1. **API and endpoint.** Provider (R2 or S3), region or jurisdiction, API (PutObject / UploadPart), and the exact request headers used for `If-None-Match` and `If-Match`. R2 and S3 have not always offered the same conditional headers. Record the documentation revision that was read.
2. **Create.** Two concurrent `PutObject` calls with `If-None-Match: *` and different bodies. Exactly one must succeed. The other must fail without leaving a mix of the two bodies. Record both HTTP statuses.
3. **Replace.** `PutObject` with `If-Match` equal to the current etag succeeds and returns a new etag. The same call with a stale etag fails and the previous body is still what `GetObject` returns.
4. **Lost response.** A client that times out after the server has committed must retry and observe the winner, not publish a second HEAD. Describe the retry rule that was tested.
5. **Read-after-write.** A `GetObject` immediately after a successful conditional put returns the new body and the new etag, from the same endpoint class the product will use.
6. **Etag meaning.** Confirm whether the etag changes when the body changes, whether it is quoted, and whether it is an MD5. Do not use an MD5 etag as a plaintext identifier. The product etag is only a compare-and-swap token.
7. **Overwrite without the precondition.** A put that omits the conditional header must be treated as a failed experiment if the provider still overwrites. The adapter must refuse to send that request.
8. **Durability wording.** Record what the provider documents for a successful put (for example, whether the new object is durable before the response). This plan does not convert that wording into a product claim.

Until those eight records exist for one provider, PLAN item 24 stays open and no cloud adapter is linked into the vault.
