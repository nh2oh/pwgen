//
 // pw_phonemes.c --- generate secure passwords using phoneme rules
 //
 // Copyright (C) 2001,2002 by Theodore Ts'o
 // 
 // This file may be distributed under the terms of the GNU Public
 // License.
 //

#include <string>
#include <random>
#include <algorithm>
#include "pwgen.h"

pw_element elements[] = {
	{ "a",	eflag::is_vowel },
	{ "ae", eflag::is_vowel | eflag::is_dipthong },
	{ "ah",	eflag::is_vowel | eflag::is_dipthong },
	{ "ai", eflag::is_vowel | eflag::is_dipthong },
	{ "b",  eflag::is_consonant },
	{ "c",	eflag::is_consonant },
	{ "ch", eflag::is_consonant | eflag::is_dipthong },
	{ "d",	eflag::is_consonant },
	{ "e",	eflag::is_vowel },
	{ "ee", eflag::is_vowel | eflag::is_dipthong },
	{ "ei",	eflag::is_vowel | eflag::is_dipthong },
	{ "f",	eflag::is_consonant },
	{ "g",	eflag::is_consonant },
	{ "gh", eflag::is_consonant | eflag::is_dipthong | eflag::not_first },
	{ "h",	eflag::is_consonant },
	{ "i",	eflag::is_vowel },
	{ "ie", eflag::is_vowel | eflag::is_dipthong },
	{ "j",	eflag::is_consonant },
	{ "k",	eflag::is_consonant },
	{ "l",	eflag::is_consonant },
	{ "m",	eflag::is_consonant },
	{ "n",	eflag::is_consonant },
	{ "ng",	eflag::is_consonant | eflag::is_dipthong | eflag::not_first },
	{ "o",	eflag::is_vowel },
	{ "oh",	eflag::is_vowel | eflag::is_dipthong },
	{ "oo",	eflag::is_vowel | eflag::is_dipthong},
	{ "p",	eflag::is_consonant },
	{ "ph",	eflag::is_consonant | eflag::is_dipthong },
	{ "qu",	eflag::is_consonant | eflag::is_dipthong},
	{ "r",	eflag::is_consonant },
	{ "s",	eflag::is_consonant },
	{ "sh",	eflag::is_consonant | eflag::is_dipthong},
	{ "t",	eflag::is_consonant },
	{ "th",	eflag::is_consonant | eflag::is_dipthong},
	{ "u",	eflag::is_vowel },
	{ "v",	eflag::is_consonant },
	{ "w",	eflag::is_consonant },
	{ "x",	eflag::is_consonant },
	{ "y",	eflag::is_consonant },
	{ "z",	eflag::is_consonant }
};

//#define NUM_ELEMENTS (sizeof(elements) / sizeof (struct pw_element))

std::string pw_phonemes(const pw_opts_t& opts) {
	const char *pw_digits = "0123456789";
	const char *pw_uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const char *pw_lowers = "abcdefghijklmnopqrstuvwxyz";
	const char *pw_symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	const char *pw_ambiguous = "B8G6I1l0OQDS5Z2";
	const char *pw_vowels = "01aeiouyAEIOUY";

	// Replaces pw_number(int); pw_number(i) returns on [0,i)
	std::default_random_engine re {};
	std::uniform_int_distribution rd_elem {0, sizeof(elements)/sizeof(pw_element)};
	std::uniform_int_distribution rd_vc {0,1};  // should_be = pw_number(2) ? VOWEL : CONSONANT;
	std::uniform_int_distribution rd_vc_next {0,9};  // should_be = pw_number(10) > 3 ? VOWEL : CONSONANT;
	std::uniform_int_distribution rd_uc {0,10};  // Decrement???
	std::uniform_int_distribution rd_digits {0,9};  // if (pw_number(10) < 3) ...
	std::uniform_int_distribution rd_rand_digit {0,9};
	std::uniform_int_distribution rd_symbols {0,9};  // pw_number(10) < 2 ...
	std::uniform_int_distribution rd_rand_symb {0,strlen(pw_symbols)};

	//pw_opts_t opts_copy {opts};
	std::string passwd {};
	eflag should_be_vc {(rd_vc(re) > 0) ? eflag::is_vowel : eflag::is_consonant};
	optflag passwd_satisfies {};  // Not sure how to default-construct
	bool require_first {true};
	pw_element prev_elem;  // note:  declared uninitialized :(
	while (passwd.size() < opts.pw_length) {
		pw_element curr_elem = elements[rd_elem(re)];
		
		if (curr_elem.flags & should_be_vc) { continue; }
		if (require_first && (curr_elem.flags & eflag::not_first)) { continue; }
		// Don't allow VOWEL followed a Vowel/Dipthong pair 
		// prev_flag not initialized
		if (passwd.size() > 0 && require_first && (prev_elem.flags & eflag::is_vowel) 
			&& (curr_elem.flags & eflag::is_vowel) && (curr_elem.flags & eflag::is_dipthong)) {
			continue;
		}
		// Flag "vowels" means "Don't use vowels" but i can't see where this is enforced

		// Ambiguous flag:  "Don't include ambiguous characters"
		// Search curr_elem for a char from the ambiguous set.  If found, do not add to passwd.  
		if (opts.no_ambiguous) {
			auto it = std::find_first_of(curr_elem.str.begin(),curr_elem.str.end(),
				pw_ambiguous.begin(),pw_ambiguous.end());
			if (it != curr_elem.str.end()) { continue; }
		}

		// curr_elem is acceptable, but do not add it to passwd until after the uppers flag has
		// been processed.  
		
		// Uppers flag:  Require >= 1 uc char
		// If the curr_elem is a consonant or the current pos in passwd is a 'first' position,
		// convert curr_elem to upper.  passwd now satisfies the uppers flags, so set opts_copy
		// to reflect this.  
		// Does not assume elem added to passwd; his version mutates passwd directly
		if (opts.uppers) {  // Require >= 1 uc char
			if ((require_first || curr_elem.flags & eflag::is_consonant) && (rd_uc(re) < 2)) {
				std::transform(curr_elem.str.begin(),curr_elem.str.end(),str.begin(),::toupper);
				passwd_satisfies &= ~optflag::require_uppers;
			}
		}

		passwd += curr_elem.str;

		// Digits flag:  Require >= 1 digit
		// If the ambiguous flag is set, pick a random element from pw_digits not found in 
		// pw_ambiguous (contains 8,6,1,0,5,2).  If the ambiguous flag is not set, any pw_digits
		// element will do.  
		if (opts.digits && !require_first && (rd_digits(re) < 3)) {
			char ch;
			do {
				ch = pw_digits[rd_rand_digit(re)];
			} while (opts.no_ambiguous 
				&& std::find(pw_ambiguous.begin(),pw_ambiguous.end(),ch)!=pw_ambiguous.end());
				
			passwd += ch;

			// passwd now satisfies the digits flag
			passwd_satisfies &= ~optflag::require_digits;
				
			should_be_vc = (rd_vc(re) > 0) ? eflag::vowel : eflag::consonant;
			require_first = false;
			continue;
		}

		// Symbols flag:  Require >= 1 symbol
		// If the current position in passwd is a non-"first" location, add a symbol
		if (opts.symbols) {
			if (!require_first && (rd_symbols(re) < 2)) {
				char ch;
				do {
					ch = pw_symbols[rd_rand_symb(re)];
				} while (opts.ambiguous
					&& std::find(pw_ambiguous.begin(),pw_ambiguous.end(),rdigit)!=pw_ambiguous.end());
				passwd_satisfies &= ~optflag::require_symbols;
				passwd += ch;
			}
		}

		// Figure out what the next element should be
		if (should_be_vc == eflag::consonant) {
			should_be_vc = eflag::vowel;
		} else { // should_be == eflag::vowel 
			// prev_elem uninitialized on first iteration
			if ((prev_elem.flags & eflag::vowel) || (curr_elem.flags & eflag::dipthong) || (rd_vc_next(re) > 3)) {
				should_be_vc = eflag::consonant;
			} else {
				should_be_vc = eflag::vowel;
			}
		}

		require_first = false;
		pw_element prev_elem = curr_elem;

		if (passwd.size() == opts.pw_length) {
			if (passwd_satisfies & (optflag::require_uppers | optflag::require_digits | optflag::require_symbols)) {
				passwd.clear();
				require_first = true;
				should_be_vc = 0;
				// prev_elem = ... need to clear...
				// passwd_satisfies = ... need to clear ...
			}
		}

	}

	return passwd;
}


/*
void pw_phonemes(char *buf, int size, int pw_flags, char *remove)
{
	int		c, i, len, flags, feature_flags;
	int		prev, should_be, first;
	const char	*str;
	char		ch, *cp;

try_again:
	feature_flags = pw_flags;
	c = 0;
	prev = 0;
	should_be = 0;
	first = 1;

	should_be = pw_number(2) ? VOWEL : CONSONANT;
	
	while (c < size) {
		i = pw_number(NUM_ELEMENTS);
		str = elements[i].str;
		len = strlen(str);
		flags = elements[i].flags;
		// Filter on the basic type of the next element //
		if ((flags & should_be) == 0)
			continue;
		// Handle the NOT_FIRST flag //
		if (first && (flags & NOT_FIRST))
			continue;
		// Don't allow VOWEL followed a Vowel/Dipthong pair //
		if ((prev & VOWEL) && (flags & VOWEL) &&
		    (flags & DIPTHONG))
			continue;
		// Don't allow us to overflow the buffer //
		if (len > size-c)
			continue;

		//
		 * OK, we found an element which matches our criteria,
		 * let's do it!
		 //
		strcpy(buf+c, str);

		// Handle PW_UPPERS //
		if (pw_flags & PW_UPPERS) {
			if ((first || flags & CONSONANT) &&
			    (pw_number(10) < 2)) {
				buf[c] = toupper(buf[c]);
				feature_flags &= ~PW_UPPERS;
			}
		}

		// Handle the AMBIGUOUS flag //
		if (pw_flags & PW_AMBIGUOUS) {
			buf[c+len] = '\0'; // To make strpbrk() happy //
			cp = strpbrk(buf, pw_ambiguous);
			if (cp)
				continue;
		}
		
		c += len;
		
		// Time to stop? //
		if (c >= size)
			break;
		
		//
		 * Handle PW_DIGITS
		 //
		if (pw_flags & PW_DIGITS) {
			if (!first && (pw_number(10) < 3)) {
				do {
					ch = pw_number(10)+'0';
				} while ((pw_flags & PW_AMBIGUOUS) 
					 && strchr(pw_ambiguous, ch));
				buf[c++] = ch;
				buf[c] = 0;
				feature_flags &= ~PW_DIGITS;
				
				first = 1;
				prev = 0;
				should_be = pw_number(2) ?
					VOWEL : CONSONANT;
				continue;
			}
		}
				
		// Handle PW_SYMBOLS //
		if (pw_flags & PW_SYMBOLS) {
			if (!first && (pw_number(10) < 2)) {
				do {
					ch = pw_symbols[
						pw_number(strlen(pw_symbols))];
				} while ((pw_flags & PW_AMBIGUOUS) 
					&& strchr(pw_ambiguous, ch));
				buf[c++] = ch;
				buf[c] = 0;
				feature_flags &= ~PW_SYMBOLS;
			}
		}

		//
		 * OK, figure out what the next element should be
		 //
		if (should_be == CONSONANT) {
			should_be = VOWEL;
		} else { // should_be == VOWEL //
			if ((prev & VOWEL) ||
			    (flags & DIPTHONG) ||
			    (pw_number(10) > 3))
				should_be = CONSONANT;
			else
				should_be = VOWEL;
		}
		prev = flags;
		first = 0;
	}
	if (feature_flags & (PW_UPPERS | PW_DIGITS | PW_SYMBOLS))
		goto try_again;
}*/
