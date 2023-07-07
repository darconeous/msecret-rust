#!/bin/bash
#
# "Wordy Password" - A script for creating ad-lib passphrases.
#
# Copyright 2023 Robert Quattlebaum
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# 47 bits of entropy
#PATTERN="@ADVERB@ @VERB@ @A_OR_THE@ @ADJ@ @NOUN@."

# 53 bits of entropy
#PATTERN="@ADVERB@ @VERB@ @PREPOSITION@ @A_OR_THE@ @ADJ@ @NOUN@."

# 56 bits of entropy
#PATTERN="@ON_OR_FOR@ @DATE@, @NAME@ @PAST_VERB@ @NAME@'s @ADJ@ @NOUN@."

# 64 bits of entropy
#PATTERN="@PREPOSITION@ @DATE@, @NAME@ @ADVERB@ @PAST_VERB@ @A_OR_THE@ @ADJ@ @NOUN@."

# 72 bits of entropy
#PATTERN="@A_OR_THE@ @ADJ@ @NOUN@ @ADVERB@ @PAST_VERB@ @A_OR_THE@ @ADJ@ @NOUN@."

# 77 bits of entropy
#PATTERN="@ADVERB@ @VERB@ @A_OR_THE@ @ADJ@ @NOUN@ @PREPOSITION@ @A_OR_THE@ @ADJ@ @NOUN@."

# 82 bits of entropy
#PATTERN="@ADVERB@ @VERB@ @A_OR_THE@ @ADJ@ @NOUN@ @PREPOSITION@ @A_OR_THE@ @ADJ@ @NOUN@ @ON_OR_FOR@ @DATE@."

# 92 bits of entropy
PATTERN="@ADVERB@ @VERB@ @A_OR_THE@ @ADJ@ @NOUN@ @PREPOSITION@ @A_OR_THE@ @ADJ@ @NOUN@ @ON_OR_FOR@ @DATE@ @IN_OR_AROUND@ @PLACE@."

# Add 10 bits of entropy by appending a random number between 1 and 999.
#PATTERN="${PATTERN} @RAND_999@"

# Add 13 bits of entropy by appending a random number between 1 and 9999.
#PATTERN="${PATTERN} @RAND_9999@"

#################################################################

msecretctl --rand-secret int 10 2>&1 1>/dev/null || {
    echo "msecretctl not found or not usable"
    exit -1
}

#################################################################

VERB_LIST=verb.txt
NOUN_LIST=noun.txt
DATE_LIST=date.txt
PLACE_LIST=place.txt
NAME_LIST=name.txt
ADJ_LIST=adj.txt
ADVERB_LIST=adverb.txt
PREPOSITION_LIST=preposition.txt

# Count all of the words in the word lists.
VERB_COUNT=`wc -l < "$VERB_LIST"`
NOUN_COUNT=`wc -l < "$NOUN_LIST"`
ADJ_COUNT=`wc -l < "$ADJ_LIST"`
DATE_COUNT=`wc -l < "$DATE_LIST"`
NAME_COUNT=`wc -l < "$NAME_LIST"`
PLACE_COUNT=`wc -l < "$PLACE_LIST"`
ADVERB_COUNT=`wc -l < "$ADVERB_LIST"`
PREPOSITION_COUNT=`wc -l < "$PREPOSITION_LIST"`

COMBINATION_COUNT_FILE=`mktemp`

cleanup() {
    rm -fr "${COMBINATION_COUNT_FILE}"
    PASSWORD=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    unset PASSWORD
}

echo 1 >"${COMBINATION_COUNT_FILE}"

# Returns a random number in the range [1, $1].
random_number() {
	local max=$1
	ENTROPY=`cat $COMBINATION_COUNT_FILE`
	echo "$ENTROPY * $max" | bc > $COMBINATION_COUNT_FILE

	msecretctl --rand-secret int $max --skip-zero
}

random_verb() {
	line=`random_number $VERB_COUNT`
	head -n $line "$VERB_LIST" | tail -n 1
}

random_past_verb() {
	# Kinda shady...
	printf "%sed" "`random_verb | sed 's/e$//'`" | sed 's/inged$/ang/'
}

random_noun() {
	line=`random_number $NOUN_COUNT`
	head -n $line "$NOUN_LIST" | tail -n 1
}

random_name() {
	line=`random_number $NAME_COUNT`
	head -n $line "$NAME_LIST" | tail -n 1
}

random_place() {
	line=`random_number $PLACE_COUNT`
	head -n $line "$PLACE_LIST" | tail -n 1
}

random_date() {
	line=`random_number $DATE_COUNT`
	head -n $line "$DATE_LIST" | tail -n 1
}

random_adj() {
	line=`random_number $ADJ_COUNT`
	head -n $line "$ADJ_LIST" | tail -n 1
}

random_adverb() {
	line=`random_number $ADVERB_COUNT`
	head -n $line "$ADVERB_LIST" | tail -n 1
}

random_preposition() {
	line=`random_number $PREPOSITION_COUNT`
	head -n $line "$PREPOSITION_LIST" | tail -n 1
}

combinations_to_bits_of_entropy() {
	echo "scale=5; l($1)/l(2)" | bc -l
}

pattern_gen() {
	local pattern="$@"
	local tag=
	local value=
	shift


	while echo "$pattern" | grep -q "@[A-Z_0-9]*@"
	do
		tag="`echo "$pattern" | sed 's/[^@]*@\([A-Z_0-9]*\)@.*/\1/'`"
		case $tag in
		ADVERB)
			value=`random_adverb`
			;;
		VERB)
			value=`random_verb`
			;;
		PAST_VERB)
			value=`random_past_verb`
			;;
		ADJ)
			value=`random_adj`
			;;
		NOUN)
			value=`random_noun`
			;;
		DATE)
			value=`random_date`
			;;
		NAME)
			value=`random_name`
			;;
		PLACE)
			value=`random_place`
			;;
		PREPOSITION)
			value=`random_preposition`
			;;
		RAND_999)
			value=`random_number 999`
			;;
		RAND_9999)
			value=`random_number 9999`
			;;
		RAND_99999)
			value=`random_number 99999`
			;;
		RAND_999999)
			value=`random_number 999999`
			;;
		A_OR_THE)
			case `random_number 2` in
			1) value="a";;
			2) value="the";;
			esac
			;;
		IN_OR_AROUND)
			case `random_number 9` in
			1) value="in";;
			2) value="around";;
			3) value="close to";;
			4) value="far away from";;
			5) value="near";;
			6) value="nowhere near";;
			7) value="somewhere in";;
			8) value="somewhere around";;
			9) value="somewhere close to";;
			esac
			;;
		ON_OR_FOR)
			case `random_number 4` in
			1) value="on";;
			2) value="for";;
			3) value="after";;
			4) value="before";;
			esac
			;;
		*)
			echo "Error: Bad pattern" > /dev/stderr
			exit 1
			;;
		esac

		pattern="`echo "$pattern" | sed "s/@$tag@/$value/;s/ a \([aeiou]\)/ an \1/; "`"
	done

	pattern="$(tr '[:lower:]' '[:upper:]' <<< ${pattern:0:1})${pattern:1}"
	pattern="`echo "$pattern" | sed "s/_/ /g;s/ on yesterday/ yesterday/g;s/ on tomorrow/ tomorrow/g;"`"
	printf %s "$pattern"
}

naive_entropy() {
	local count=`printf "$@" | wc -c`
	local bits=4+$count;

	if [ $count -lt 20 ]
	then bits=$((bits+count/2))
	else bits=$((bits+10))
	fi

	if [ $count -lt 8 ]
	then bits=$((bits+count/2))
	else bits=$((bits+4))
	fi

	echo $bits
}

# Calculate the passphrase
PASSWORD="`pattern_gen "$PATTERN"`"

(
	ENTROPY=`cat $COMBINATION_COUNT_FILE`
	echo "Pattern Entropy: " `combinations_to_bits_of_entropy $ENTROPY`
	echo "Naive Entropy: " `naive_entropy "$PASSWORD"`
) > /dev/stderr

printf "%s" "${PASSWORD}"

cleanup

[ -t 0 ] && echo
