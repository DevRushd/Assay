# synthetic-redirect-off-host — cross-host redirect refusal fixture

Not a live subject. Built to exercise the cross-host redirect refusal rule in
SEP-1 well-known toml resolution (#380).

The issuer advertises home_domain "redirect.example". When fetching
`https://redirect.example/.well-known/stellar.toml`, the server responds with a
recorded redirect chain that leaves the requested host namespace:

    https://redirect.example/.well-known/stellar.toml (302)
    -> https://redirect.example/hop/1 (302)
    -> https://other.example/.well-known/stellar.toml (refused by redirect policy)

The redirect rule refuses the hop because `other.example` is an unrelated host.
`stellar.toml.err` records the refusal error verbatim:

    sep1: fetch https://redirect.example/.well-known/stellar.toml: Get "https://other.example/.well-known/stellar.toml": cross-host redirect from redirect.example to other.example

The resulting report must have accountability: unverified and state the refused host
("other.example") in its evidence and reasoning.
