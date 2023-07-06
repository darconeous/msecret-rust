# Wordy Password #

This is a fun shell script which uses `msecretctl` to make strong
passphrases that are memorable to native English speakers, like these:

*   `Swiftly pot a definitive stepdaughter.`
*   `Underneath Christmas Day, Roger disquietingly subvocalized a blind whistle.`
*   `Touchingly compartmentalize an indiscriminating gosling among the frigid recess on Armed Forces Day.`

This approach is ideal for the few cases where you actually need to
remember a password.

It works a bit like [Mad-Libs](https://en.wikipedia.org/wiki/Mad_Libs):
A pattern is used to pick words from various lists so that they can be
put together into a silly phrase that you can remember.


## Patterns ##

There are currently several different patterns. Edit [the script](wordy-password.sh) to change the pattern.

* 47 bits of entropy: `@ADVERB@ @VERB@ @A_OR_THE@ @ADJ@ @NOUN@.`
* 53 bits of entropy: `@ADVERB@ @VERB@ @PREPOSITION@ @A_OR_THE@ @ADJ@ @NOUN@.`
* 56 bits of entropy: `@ON_OR_FOR@ @DATE@, @NAME@ @PAST_VERB@ @NAME@'s @ADJ@ @NOUN@.`
* 64 bits of entropy: `@PREPOSITION@ @DATE@, @NAME@ @ADVERB@ @PAST_VERB@ @A_OR_THE@ @ADJ@ @NOUN@.`
* 72 bits of entropy: `@A_OR_THE@ @ADJ@ @NOUN@ @ADVERB@ @PAST_VERB@ @A_OR_THE@ @ADJ@ @NOUN@.`
* 77 bits of entropy: `@ADVERB@ @VERB@ @A_OR_THE@ @ADJ@ @NOUN@ @PREPOSITION@ @A_OR_THE@ @ADJ@ @NOUN@.`
* 82 bits of entropy: `@ADVERB@ @VERB@ @A_OR_THE@ @ADJ@ @NOUN@ @PREPOSITION@ @A_OR_THE@ @ADJ@ @NOUN@ @ON_OR_FOR@ @DATE@.`
* 92 bits of entropy: `@ADVERB@ @VERB@ @A_OR_THE@ @ADJ@ @NOUN@ @PREPOSITION@ @A_OR_THE@ @ADJ@ @NOUN@ @ON_OR_FOR@ @DATE@ @IN_OR_AROUND@ @PLACE@.`

Some additional entropy can be added by appending random numbers using
`@RAND_999@` (~10 additional bits) or `@RAND_9999@` (~13 additional bits).

Nore that the entropy figures above are the guaranteed minimum entropy
assuming that an attacker knows the pattern and the word lists. If the size
of the word lists change, the entropy value wil also change. The script will
print out the exact entropy of the generated passphrase.

See [the script](wordy-password.sh) for more details.

## Dependencies ##

Obviously, this script depends on `msecretctl` to calculate random
integers with a uniform distribution. It also depends on the `bc` tool
for calculating the entropy. The script also uses `sed`, `head`,
`printf`, etc. Typical shell-script stuff.

The script is known to work on Macs, but would likely work on Linux as
well.

## Improvements ##

Obviously, being a shell script makes this a bit more obtuse to use.
Rewriting it in Rust would be an obvious win in my book.

Improving the word list would also be beneficial. It would also make
the resulting passphrases contain more entropy, although the returns
on this are diminishing.

Adding more patterns would also be nice.

It would be great to have this functionality integrated into
[msecret](https://github.com/darconeous/msecret-rust) itself, but then
repeatability becomes an important consideration (so the word list
would need to be crystalized and never change after that).
