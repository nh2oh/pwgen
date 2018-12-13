// pw_phonemes.cpp --- generate secure passwords using phoneme rules
// Copyright (C) 2018 by Ben Knowles
// Copyright (C) 2001,2002 by Theodore Ts'o
 // This file may be distributed under the terms of the GNU Public License.
 //

#include <string>
#include <random>
#include <algorithm>
#include "pwgen.h"


// is_consonant iff it starts w/a consonant (ex: "qu"); if contains, but does 
// not start w/a consonant, does not get is_consonant (ex: "ah").  
// is_vowel iff it starts w/a vowel (ex: "ah"); if contains, but does not start 
// w/a vowel, does not get is_vowel (ex: "qu").  
// is_vowel, is_consonant are mutually exclusive
// is_dipthong iff 2 letters.  
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
	//opts.no_vowels is not enforced

	std::string pw_digits_all = {"0123456789"};
	std::string pw_symbols_all = {"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"};
	std::string pw_ambiguous_all = {"B8G6I1l0OQDS5Z2"};

	auto contains_ambiguous = [pw_ambiguous](const std::string& s) -> bool {
		auto it = std::find_first_of(s.begin(),s.end(),
				pw_ambiguous.begin(),pw_ambiguous.end());
		return it == s.end();
	};

	std::string pw_digits {}; std::string pw_symbols {};
	if (opts.no_ambiguous) {
		std::set_difference(pw_digits_all.begin(),pw_digits_all.end(),
			pw_ambiguous.begin(),pw_ambiguous.end(),std::back_inserter(pw_digits));

		std::set_difference(pw_symbols_all.begin(),pw_symbols_all.end(),
			pw_ambiguous.begin(),pw_ambiguous.end(),std::back_inserter(pw_symbols));
	}

	// Replaces pw_number(int); pw_number(i) returns on [0,i)
	std::default_random_engine re {};

	auto rand_char = [&re](const std::string& s) -> char {
		std::uniform_int_distribution rd {0,s.size()-1};
		return s[rd(re)];
	};
	auto rand_elem = [&re,&elements]() -> char {
		std::uniform_int_distribution rd {0,sizeof(elements)/sizeof(pw_element)-1};
		return elements[rd(re)];
	};
	auto randdig = [&re]() -> int {
		std::uniform_int_distribution rd {0,9};
		return rd(re);
	};

	std::string passwd {};
	elem_properties_t rq_curr_elem {};
	eflag rq_prev_elem {eflag::none};  // requirements for the prev element
	optflag passwd_satisfies {};  // Not sure how to default-construct

	pw_element curr_elem;  // uninit :(
	pw_element prev_elem;  // uninit :(
	while (passwd.size() < opts.pw_length) {
		if (passwd.size() == 0) {
			passwd_satisfies = optflag::none;
			rq_curr_elem.reset();
			
			if (randdig()>4) {  //rq_curr_elem &= ((randdig()>4) ? eflag::is_vowel : eflag::is_consonant;
				rq_curr_elem.is_vowel(true);
			} else {
				rq_curr_elem.is_consonant(true);
			}
		} else {  // Not the first iter
			if (rq_prev_elem.is_consonant()) {
				rq_curr_elem.is_vowel(true);
			} else {
				// on prev iter rq_curr_elem was !eflag::is_consonant ... does not mean eflag::is_vowel; 
				// could be !eflag::is_consonant and !eflag::is_vowel
				if ((prevprev_elem.flags & eflag::is_vowel) 
					|| (prev_elem.flags & eflag::is_dipthong) 
					|| (randdig() > 3)) {
					rq_curr_elem.is_consonant(true); //rq_curr_elem |= eflag::consonant;
				} else {
					rq_curr_elem.is_vowel(true); //rq_curr_elem |= eflag::vowel;
				}
			}

			if (std::stoi(passwd.back()) >= 0 && std::stoi(passwd.back()) <= 9) {
				//rq_curr_elem = ((randdig()>4) ? eflag::vowel : eflag::consonant;  // NB intentional overwriting w/ =
				rq_curr_elem = elem_properties_t {};
				if (randdig()>4) {
					rq_curr_elem.is_vowel(true);
				} else {
					rq_curr_elem.is_consonant(true);
				}
				rq_curr_elem.not_first(false); //rq_curr_elem &= ~eflag::not_first;  // want: require_first = true;
			} else {
				rq_curr_elem.not_first(true); //rq_curr_elem |= eflag::not_first;  // want: "require_first = false"
			}
		}

		bool redraw {false};
		do {
			curr_elem = rand_elem();
			
			redraw = (!(curr_elem.flags & eflag::vowel) && rq_curr_elem.is_vowel())
				|| (!(curr_elem.flags & eflag::not_first) && (rq_curr_elem.not_first()))
				|| ((prev_elem.flags & eflag::is_vowel) && (curr_elem.flags & eflag::is_vowel) 
					&& (curr_elem.flags & eflag::is_dipthong));  // Forbid vowel followed by vowel/dipthong pair 
		} while (redraw);

		// Uppers flag:  Require >= 1 uc char
		if (opts.uppers) {
			if ((rq_curr_elem.not_first()==false || (curr_elem.flags & eflag::is_consonant)) 
				&& (randdig() < 2)) {
				// If the curr_elem is a consonant or the current pos is a 'first' position 
				// (wtf is with this wonky condition???), maybe convert curr_elem to upper.
				std::transform(curr_elem.str.begin(),curr_elem.str.end(),str.begin(),::toupper);
				passwd_satisfies |= optflag::require_uppers;
			}
		}

		passwd += curr_elem.str;

		// Digits flag:  Require >= 1 digit
		// If the current position in passwd is a non-"first" location, maybe append a digit.  
		if (opts.digits && rq_curr_elem.not_first() && (randdig() < 3)) {
			char ch = rand_char(pw_digits);
			passwd += ch;
			passwd_satisfies |= optflag::require_digits;
		}

		// Symbols flag:  Require >= 1 symbol
		// If the current position in passwd is a non-"first" location, maybe append a symbol.  
		if (opts.symbols && rq_curr_elem.not_first() && (randdig() < 2)) {
			char ch = rand_char(pw_symbols);
			passwd += ch;
			passwd_satisfies |= optflag::require_symbols;
		}

		prev_elem = curr_elem;
		rq_prev_elem = rq_curr_elem;

		if (passwd.size() == opts.pw_length) {
			if (passwd_satisfies & (optflag::require_uppers | optflag::require_digits | optflag::require_symbols)) {
				passwd.clear();
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
