// pw_phonemes.cpp --- generate secure passwords using phoneme rules
// Copyright (C) 2018 by Ben Knowles
// Copyright (C) 2001,2002 by Theodore Ts'o
// This file may be distributed under the terms of the GNU Public License.
//

#include <string>
#include <random>
#include <cstdlib>  // std::atoi()
#include <algorithm>
#include "pwgen.h"

// Everything has a single consonant label or a single vowel label; some items have
// addnl labels, but each element is either a vowel or consonant.  
// is_consonant iff it starts w/a consonant (ex: "qu"); if contains, but does 
// not start w/a consonant, does not get is_consonant (ex: "ah").  
// is_vowel iff it starts w/a vowel (ex: "ah"); if contains, but does not start 
// w/a vowel, does not get is_vowel (ex: "qu").  
// is_vowel, is_consonant are mutually exclusive
// is_dipthong iff 2 letters.  Dipthongs exist that are also vowels; dipthongs
// exist that not also consonants.  All dipthongs are either vowels or consonants.

// TODO:  Convert to std::array<pw_element,N>
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
	// opts.no_vowels is not enforced

	std::string pw_digits_all = {"0123456789"};
	std::string pw_symbols_all = {"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"};
	std::string pw_ambiguous_all = {"B8G6I1l0OQDS5Z2"};

	// TODO:  Not used; move to pw_rand()
	/*auto contains_ambiguous = [pw_ambiguous](const std::string& s) -> bool {
		auto it = std::find_first_of(s.begin(),s.end(),
				pw_ambiguous.begin(),pw_ambiguous.end());
		return it == s.end();
	};*/

	// TODO:  Temp Hack
	std::string pw_digits {pw_digits_all}; std::string pw_symbols {pw_symbols_all};
	/*if (opts.no_ambiguous) {
		std::set_difference(pw_digits_all.begin(),pw_digits_all.end(),
			pw_ambiguous.begin(),pw_ambiguous.end(),std::back_inserter(pw_digits));

		std::set_difference(pw_symbols_all.begin(),pw_symbols_all.end(),
			pw_ambiguous.begin(),pw_ambiguous.end(),std::back_inserter(pw_symbols));
	}*/

	// Replaces pw_number(int); pw_number(i) returns on [0,i)
	std::default_random_engine re {};

	auto rand_char = [&re](const std::string& s) -> char {
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

	std::string passwd {};
	//elem_properties_t rq_curr_elem {};  // Requirements for the current element
	elem_rq rq_ce {};
	struct passwd_features_t {
		bool has_upper {false};
		bool has_digit {false};
		bool has_symbol {false};
	};
	passwd_features_t curr_pw_props {};

	pw_element curr_elem;  // uninit :(
	pw_element prev_elem;  // uninit :(
	while (passwd.size() < opts.pw_length) {
		if (passwd.size() == 0) {  // First iter
			rq_ce &= rqflag::first;
			if (randdig()>4) { rq_ce &= rqflag::vowel; }
			//rq_ce &= (randdig()>4) ? rqflag::vowel : 0;
			//rq_curr_elem.set(elem_properties_t::flag::not_first,elem_properties_t::flag::forbid);
				// Can't start the passwd w/ something marked "not first."  
			//rq_curr_elem.set(elem_properties_t::flag::vowel,(randdig()>4));

		} else {  // Not the first iter
			if (prev_elem.flags & eflag::is_consonant) {
				rq_ce &= rqflag::vowel;
				//rq_curr_elem.set(elem_properties_t::flag::vowel,elem_properties_t::mode::require);
					// consonants are _always_ followed by vowels (c-v || c-dv); forbids c-dc
			} else {  // prev elem was a vowel
				if (randdig()>3) { rq_ce &= rqflag::vowel; }
				//rq_ce &= (randdig()<=3) ? rqflag::vowel : 0;
				rq_ce &= ~rqflag::dipthong;
				//rq_curr_elem.set(elem_properties_t::flag::vowel,(randdig()<=3));
				//rq_curr_elem.set(elem_properties_t::flag::dipthong,elem_properties_t::mode::forbid);
					// vowels are _never_ followed by dipthongs
			}

			if (std::atoi(&passwd.back()) >= 0 && std::atoi(&passwd.back()) <= 9) {
				rq_ce &= rqflag::first;
				if (randdig()>4) { rq_ce &= rqflag::vowel; }
				//rq_ce &= (randdig()>4) ? rqflag::vowel : 0;
				//rq_curr_elem.set(elem_properties_t::flag::vowel,(randdig()>4));
				//rq_curr_elem.set(elem_properties_t::flag::not_first,elem_properties_t::mode::forbid);
				// Can't pick up after a digit w/ something marked "not first."  These are the
				// same conditions as are set on the very first iter.  
			} else {
				rq_ce &= ~rqflag::first;
				//rq_curr_elem.set(elem_properties_t::flag::not_first,elem_properties_t::mode::require);
			}
		}

		bool success {false};
		do {
			curr_elem = rand_elem();
			success = rq_ce && curr_elem.flags;
			//bool success = rq_curr_elem.satisfied(elem_properties_t::flag::vowel, (curr_elem.flags & elem_properties_t::flag::vowel))
			//	&& rq_curr_elem.satisfied(elem_properties_t::flag::not_first, (curr_elem.flags & elem_properties_t::flag::not_first))
			//	&& rq_curr_elem.satisfied(elem_properties_t::flag::dipthong, (curr_elem.flags & elem_properties_t::flag::dipthong));
		} while (!success);

		// Uppers flag:  Require >= 1 uc char
		if (opts.uppers) {
			// TODO:  test for _requires_ first vs _tolerates_ first ???
			if (((rq_ce && rqflag::first) || (curr_elem.flags & eflag::is_consonant)) && (randdig() < 2)) {
			//if ((rq_curr_elem.forbids(elem_properties_t::flag::not_first) || (curr_elem.flags & eflag::is_consonant)) 
			//	&& (randdig() < 2)) {
				// If the curr_elem is a consonant or the current pos is a 'first' position, 
				// maybe convert curr_elem to upper.  
				//std::string curr_str {curr_elem.str};
				std::transform(curr_elem.str.begin(),curr_elem.str.end(),curr_elem.str.begin(),::toupper);
				curr_pw_props.has_upper = true;
			}
		}

		passwd += curr_elem.str;

		// Digits flag:  Require >= 1 digit
		// If the current position in passwd is a non-"first" location, maybe append a digit.  
		if (opts.digits && (rq_ce && ~rqflag::first) && (randdig() < 3)) {
		//if (opts.digits 
		//	&& rq_curr_elem.requires(elem_properties_t::flag::not_first) && (randdig() < 3)) {
			passwd += rand_char(pw_digits);
			curr_pw_props.has_digit = true;
		}

		// Symbols flag:  Require >= 1 symbol
		// If the current position in passwd is a non-"first" location, maybe append a symbol.  
		if (opts.symbols && (rq_ce && ~rqflag::first) && (randdig() < 2)) {
		//if (opts.symbols
		//	&& rq_curr_elem.requires(elem_properties_t::flag::not_first)
		//	&& (randdig() < 2)) {
			passwd += rand_char(pw_symbols);
			curr_pw_props.has_symbol = true;
		}

		prev_elem = curr_elem;
		rq_ce.reset();
		//rq_curr_elem.reset();

		if (passwd.size() >= opts.pw_length) {
			if ((opts.uppers && !curr_pw_props.has_upper) 
				|| (opts.digits && !curr_pw_props.has_digit) 
				|| (opts.symbols && !curr_pw_props.has_symbol)) {
				// The current passwd is the correct length but does not have all the 
				// features required by opts; restart
				passwd.clear();
				rq_ce.reset();
				//rq_curr_elem.reset();
				curr_pw_props = passwd_features_t {};
			}
		}

	}
	
	
	/*constexpr rqflag fv = rqflag::vowel;
	constexpr rqflag ff = rqflag::first;
	constexpr rqflag_forbid fff = ~rqflag::first;

	elem_rq rqs {};
	constexpr auto x = rqs &= fv;
	constexpr int p1 = x.rq_[0];*/
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
