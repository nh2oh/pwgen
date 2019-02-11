// pw_phonemes.cpp --- generate secure passwords using phoneme rules
// Copyright (C) 2018, 2019 by Ben Knowles
// Copyright (C) 2001, 2002 by Theodore Ts'o
// This file may be distributed under the terms of the GNU Public License.
//

#include <string>
#include <random>
#include <cstdlib>  // std::atoi()
#include <algorithm>
#include "pwgen.h"

//
// Everything has a single consonant label or a single vowel label; some items have
// addnl labels, but each element is either a vowel or consonant.  
// is_consonant iff it starts w/a consonant (ex: "qu"); if contains, but does 
// not start w/a consonant, does not get is_consonant (ex: "ah").  
// -> is_vowel iff it starts w/a vowel (ex: "ah"); if contains, but does not start 
//    w/a vowel, does not get is_vowel (ex: "qu").  
//    is_vowel, is_consonant are mutually exclusive
// -> is_dipthong iff 2 letters.  Dipthongs exist that are also vowels (ex: "ae," "ah");
//    dipthongs exist that are also consonants (ex: "ch," "qu").  
//    All dipthongs are either vowels or consonants.
//

// TODO:  Convert to std::array<pw_element,N>
pw_element elements[] = {
	{ "a",	eflag::vowel | eflag::first},
	{ "ae", eflag::vowel | eflag::dipthong | eflag::first},
	{ "ah",	eflag::vowel | eflag::dipthong | eflag::first},
	{ "ai", eflag::vowel | eflag::dipthong | eflag::first},
	{ "b",  eflag::first},
	{ "c",	eflag::first},
	{ "ch", eflag::dipthong | eflag::first},
	{ "d",	eflag::first},
	{ "e",	eflag::vowel | eflag::first },
	{ "ee", eflag::vowel | eflag::dipthong | eflag::first},
	{ "ei",	eflag::vowel | eflag::dipthong | eflag::first},
	{ "f",	eflag::first},
	{ "g",	eflag::first},
	{ "gh", eflag::dipthong},  // NB: !first
	{ "h",	eflag::first},
	{ "i",	eflag::vowel | eflag::first},
	{ "ie", eflag::vowel | eflag::dipthong | eflag::first},
	{ "j",	eflag::first},
	{ "k",	eflag::first},
	{ "l",	eflag::first},
	{ "m",	eflag::first},
	{ "n",	eflag::first},
	{ "ng",	eflag::dipthong},  // NB: !first
	{ "o",	eflag::vowel | eflag::first},
	{ "oh",	eflag::vowel | eflag::dipthong | eflag::first},
	{ "oo",	eflag::vowel | eflag::dipthong | eflag::first},
	{ "p",	eflag::first},
	{ "ph",	eflag::dipthong | eflag::first},
	{ "qu",	eflag::dipthong | eflag::first},
	{ "r",	eflag::first},
	{ "s",	eflag::first},
	{ "sh",	eflag::dipthong},
	{ "t",	eflag::first},
	{ "th",	eflag::dipthong | eflag::first},
	{ "u",	eflag::vowel | eflag::first},
	{ "v",	eflag::first},
	{ "w",	eflag::first},
	{ "x",	eflag::first},
	{ "y",	eflag::first},
	{ "z",	eflag::first}
};
//#define NUM_ELEMENTS (sizeof(elements) / sizeof (struct pw_element))



std::string pw_phonemes(const pw_opts_t& opts) {
	// opts.no_vowels is not enforced

	std::string pw_digits_all = {"0123456789"};
	std::string pw_symbols_all = {"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"};
	std::string pw_ambiguous_all = {"B8G6I1l0OQDS5Z2"};

	std::string pw_digits {pw_digits_all};
	std::string pw_symbols {pw_symbols_all};

	std::default_random_engine re {};

	auto rand_char = [&re](const std::string& s) -> char {
		if (s.size() == 0) {
			std::abort();
		}
		std::uniform_int_distribution rd {static_cast<size_t>(0),s.size()-1};
		return s[rd(re)];
	};
	auto rand_elem = [&re]() -> pw_element {
		std::uniform_int_distribution rd {static_cast<size_t>(0),sizeof(elements)/sizeof(pw_element)-1};
		return elements[rd(re)];  // elements is a global var
	};
	auto randdig = [&re]() -> int {
		std::uniform_int_distribution rd {static_cast<size_t>(0),static_cast<size_t>(9)};
		return rd(re);
	};

	std::string passwd {};  passwd.reserve(opts.pw_length);
	struct passwd_features_t {
		bool has_upper {false};
		bool has_digit {false};
		bool has_symbol {false};
	};
	passwd_features_t curr_pw_features {};

	pw_element curr_elem;
	pw_element prev_elem;
	while (passwd.size() < opts.pw_length) {
		curr_elem = rand_elem();

		if (passwd.size() == 0) {  // First iter
			if (!(curr_elem.flags & eflag::first)) {
				continue;
			}
			if (randdig()>4 && !(curr_elem.flags & eflag::vowel)) {
				continue;
			}
		} else {  // Not the first iter
			if (!(prev_elem.flags & eflag::vowel)) {  // prev_elem was a consonant
				if (!(curr_elem.flags & vowel)) {
					continue;
				}
			} else {  // prev elem was a vowel
				// Want to allow elements that are one of vowel, dipthong, but forbid elements
				// that are _both_ vowel, dipthong
				if ((curr_elem.flags & eflag::vowel) && (curr_elem.flags & eflag::dipthong)) {
					continue;
				}
				if (randdig()>3 && !(curr_elem.flags & eflag::vowel)) {
					continue;
				}
			}

			if (std::atoi(&passwd.back()) >= 0 && std::atoi(&passwd.back()) <= 9) {
				// Can't pick up after a digit w/ something marked "not first."  These are the
				// same conditions as are set on the very first iter.  
				if (!(curr_elem.flags & eflag::first)) {
					continue;
				}
				if (randdig()>4 && !(curr_elem.flags & eflag::vowel)) {
					continue;
				}
			} else {  // prev elem was not a digit
				// curr_require |= eflag::not_first;  // means forbid first => require not_first (?)
			}
		}

		// Uppers flag:  Require >= 1 uc char
		if (opts.uppers) {
			if (randdig() < 2)
				&& ((curr_elem.flags & eflag::first) || !(curr_elem.flags & eflag::vowel))) {
				std::transform(curr_elem.str.begin(),curr_elem.str.end(),curr_elem.str.begin(),::toupper);
				curr_pw_features.has_upper = true;
			}
		}

		passwd += curr_elem.str;

		// Digits flag:  Require >= 1 digit
		// If the current position in passwd is a non-"first" location, maybe append a digit.  
		if (opts.digits) {
			if ((randdig()<3) && !(curr_elem.flags & eflag::first)) {
				passwd += rand_char(pw_digits);
				curr_pw_features.has_digit = true;
			}
		}

		// Symbols flag:  Require >= 1 symbol
		// If the current position in passwd is a non-"first" location, maybe append a symbol.  
		if (opts.symbols) {
			if ((randdig()<2) && !(curr_elem.flags & eflag::first)) {
				passwd += rand_char(pw_symbols);
				curr_pw_features.has_symbol = true;
			}
		}

		prev_elem = curr_elem;

		if (passwd.size() >= opts.pw_length) {
			if ((opts.uppers && !curr_pw_props.has_upper) 
				|| (opts.digits && !curr_pw_props.has_digit) 
				|| (opts.symbols && !curr_pw_props.has_symbol)) {
				// The current passwd is the correct length but does not have all the 
				// features required by opts; restart
				passwd.clear();
				curr_pw_features = passwd_features_t {};
			}
		}

	}  // Generate next curr_elem
	
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
		 // Handle PW_DIGITS
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
		 // OK, figure out what the next element should be
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

