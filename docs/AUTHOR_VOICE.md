# Mdk22 author voice

This reference keeps the writing close to the author's normal explanation style. It is a tone guide, not a paragraph template.

## Core voice

- Explain the work in the same order it happened.
- Use short, ordinary sentences.
- Say what changed in the request or response before explaining why it matters.
- Use first person when it adds context, but do not begin every paragraph with `I`.
- Keep the technical detail. Simplify the sentence around it.
- Separate a confirmed result from an assumption or a possibility.
- Give failed attempts space when they helped narrow the next test.
- Do not make the Lab sound larger or more serious than the evidence shows.

## Natural sentence patterns

Prefer:

- `The normal request returned 302.`
- `Changing the username produced a different response.`
- `The same check was then repeated with curl.`
- `This was enough to confirm the route, but not a wider privilege level.`
- `The first payload did not run. It still showed where the value reached the page.`

Avoid turning these into report-style sentences such as:

- `This evidence establishes a robust and comprehensive attack primitive.`
- `A deliberately bounded request demonstrates the existence of the condition.`
- `The following article provides an evidence-backed exploration.`

## Words and patterns to review

The publication audit warns about these because a simpler sentence usually works:

- `bounded`
- `evidence-backed`
- `deliberately`
- `establishes`
- `demonstrates`
- `robust`
- `comprehensive`
- `seamless`
- em dash punctuation
- several consecutive paragraphs beginning with `I`

Do not replace a flagged word blindly. Read the paragraph and keep it when it is the clearest technical term.

## Individual story

Every case should have one detail that explains why its path was different. It may be a source comment, a response comparison, an unexpected negative result, a browser-only step, or the way two weaknesses connected.

The blog structure keeps cases organized. The wording, pacing, and amount of space given to each step should come from that case's evidence.
