# Lookalike Domains are detected with built-in rules of thumb, not a library

A domain is a Lookalike Domain when one of its labels, or one hyphenated word within a label, matches the name of a Protected Domain (its first label, `paypal` for `paypal.co.uk`) by one of five tricks: the same name reused, the name plus extra words, lookalike characters swapped in (`paypa1`, `rnicrosoft`, Cyrillic letters in `xn--` domains), or one letter off (only for names of 5 letters or more). Genuine Protected Domains and their subdomains never count. We wrote this ourselves in the standard library because each rule is a few readable lines, it adds no dependency, and the evidence can name the exact trick for the analyst.

## Considered Options

- **`tldextract` (Public Suffix List) to find the registrable domain**: more accurate about where the brand name sits, but it downloads the list at runtime unless pinned, which clashes with the tool working offline in tests. Taking the first label of each Protected Domain is good enough because the analyst lists those domains themselves.
- **`dnstwist`-style permutation generation**: generates thousands of candidate domains per brand and checks for a match. Thorough, but heavy, and harder for a beginner to read and explain.

## Consequences

- Known gaps: a brand name joined to other words without a hyphen (`paypalsecure.com`) isn't caught, and names shorter than 5 letters only match exactly or by swapped characters (so `hrmc` for `hmrc` is missed).
- Known false positives: a brand's real domains that aren't listed (`amazon.de`, `royalmail.group`) count as reusing the name, and unrelated words one letter off a brand (`apply-now.co.uk` against `apple`) fire. Analysts fix the first by adding the domain to `[brands]`; the dataset evaluation (ticket 16) will show whether the second matters.
