// pw_phonemes.cpp --- generate secure passwords using phoneme rules
// Copyright (C) 2018, 2019 by Ben Knowles
// Copyright (C) 2001, 2002 by Theodore Ts'o
// This file may be distributed under the terms of the GNU Public License.
//

#include <string>
#include <random>
#include <cstdlib>  // std::atoi()
#include <algorithm>
#include <iterator>  // std::std::back_inserter()
#include <iostream>  // only for debugging
#include "pwgen.h"
#include <array>

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


std::array<pw_element,40> elements {
	{{ "a",	eflag::vowel | eflag::first},
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
	{ "sh",	eflag::dipthong | eflag::first},   // NB: !first
	{ "t",	eflag::first},
	{ "th",	eflag::dipthong | eflag::first},
	{ "u",	eflag::vowel | eflag::first},
	{ "v",	eflag::first},
	{ "w",	eflag::first},
	{ "x",	eflag::first},
	{ "y",	eflag::first},
	{ "z",	eflag::first}}
};

constexpr bool is_consonant(int ef) {
	return !(ef & eflag::vowel);
}
constexpr bool is_vowel(int ef) {
	return (ef & eflag::vowel);
}
constexpr bool is_dipthong(int ef) {
	return (ef & eflag::dipthong);
}
constexpr bool is_vowel_and_dipth(int ef) {
	return ((ef & eflag::vowel) && (ef & eflag::dipthong));
}
constexpr bool may_appear_first(int ef) {
	return (ef & eflag::first);
}
bool is_digit(char c) {
	// std::atoi(&passwd.back()) >= 0 && std::atoi(&passwd.back()) <= 9
	std::array<char,2> str {c, '\0'};
	return std::atoi(&str[0]) >= 0 && std::atoi(&str[0]) <= 9;
}
bool debug_sanity_check_eflag_conditions(int ef) {
	if (is_vowel(ef) && is_consonant(ef)) {
		return false;
	}

	if (is_vowel_and_dipth(ef) && is_consonant(ef)) {
		return false;
	}

	if (is_vowel_and_dipth(ef) && !is_vowel(ef)) {
		return false;
	}

	return true;
}

int test_sample_if(std::mt19937& re) {
	pw_element elem;

	/*int i=0;
	while (i<1000) {
		std::sample(elements.begin(),elements.end(),&elem,1,re);
		if (!is_vowel(elem.flags)) {
			//std::cout << "what" << std::endl;
		} else {
			std::cout << elem.str << ", ";
			++i;
		}
	}*/

	auto pred_is_vowel = [](const pw_element& pwe) -> bool { return is_vowel(pwe.flags); };

	for (int i=0; i<1000; ++i) {
		sample_if(elements.begin(),elements.end(),&elem,re,pred_is_vowel);
		if (!is_vowel(elem.flags)) {
			std::cout << "what" << std::endl;
		} else {
			std::cout << elem.str << ", ";
		}
	}

	return 0;
}

int stats() {
	struct stats_t {
		int is_vowel {0};
		int is_dipth {0};
		int is_vowel_dipth {0};
		int is_consonant {0};
		int is_first {0};
	};

	stats_t counts {};
	for (int i=0; i<elements.size(); ++i) {
		counts.is_vowel += is_vowel(elements[i].flags);
		counts.is_dipth += is_dipthong(elements[i].flags);
		counts.is_vowel_dipth += is_vowel_and_dipth(elements[i].flags);
		counts.is_consonant += is_consonant(elements[i].flags);
		counts.is_first += may_appear_first(elements[i].flags);
	}

	std::cout << "is_vowel:\t" << counts.is_vowel << "\n";
	std::cout << "is_dipth:\t" << counts.is_dipth << "\n";
	std::cout << "is_vowel_dipth:\t" << counts.is_vowel_dipth << "\n";
	std::cout << "is_consonant:\t" << counts.is_consonant << "\n";
	std::cout << "is_first:\t" << counts.is_first << "\n";
	std::cout << std::endl;

	return 0;
}

std::string pw_phonemes(const pw_opts_t& opts, std::mt19937& re) {
	// opts.no_vowels is not enforced

	std::string pw_digits_all = {"0123456789"};
	std::string pw_symbols_all = {"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"};
	std::string pw_ambiguous_all = {"B8G6I1l0OQDS5Z2"};

	std::string pw_digits {pw_digits_all};
	std::string pw_symbols {pw_symbols_all};
	

	auto randdig = [&re]() -> int {
		std::uniform_int_distribution rd(0,9);
		return rd(re);
	};

	struct currfail_t {
		int a {0};
		int b {0};
		int c {0};
		int d {0};
		int e {0};
		int f {0};
		int g {0};
	};
	currfail_t currfail {};

	struct nfail_t {
		int upper {0};
		int digit {0};
		int symbol {0};
		int length {0};
	};
	nfail_t nfail {};

	std::string passwd {};  passwd.reserve(opts.pw_length);
	struct passwd_features_t {
		bool has_upper {false};
		bool has_digit {false};
		bool has_symbol {false};
	};
	passwd_features_t curr_pw_features {};

	pw_element curr_elem;
	pw_element prev_elem;
	int titer {0};
	while (passwd.size() < opts.pw_length) {
		++titer;
		//curr_elem = rand_elem();
		std::sample(elements.begin(),elements.end(),&curr_elem,1,re);

		if (!debug_sanity_check_eflag_conditions(curr_elem.flags)) {
			std::cout << "what" << std::endl;
		}

		if (passwd.size() == 0) {  // First iter
			if (!may_appear_first(curr_elem.flags)) {
				++currfail.a; continue;
			}
			if (randdig()>4 && is_consonant(curr_elem.flags)) {
				++currfail.b; continue;
			}
		} else {  // Not the first iter
			if (is_consonant(prev_elem.flags)) {  // prev_elem was a consonant
				if (!is_vowel(curr_elem.flags)) {  // a cons must always be followed by a vowel
					++currfail.c; continue;
				}
				//if (randdig()>7 && is_consonant(curr_elem.flags)) {
				//	++currfail.c; continue;
				//}
			} else {  // prev elem was a vowel
				// Want to allow elements that are one of vowel, dipthong, but forbid elements
				// that are _both_ vowel, dipthong
				if (is_vowel_and_dipth(curr_elem.flags)) {
					++currfail.d; continue;
				}
				if (randdig()>3 && !is_consonant(curr_elem.flags)) {
					++currfail.e; continue;
				}
			}

			if (is_digit(passwd.back())) {
				// Can't pick up after a digit w/ something marked "not first."  These are the
				// same conditions as are set on the very first iter.  
				if (!may_appear_first(curr_elem.flags)) {
					++currfail.f; continue;
				}
				if (randdig()>4 && is_consonant(curr_elem.flags)) {
					++currfail.g; continue;
				}
			} else {  // prev elem was not a digit
				// curr_require |= eflag::not_first;  // means forbid first => require not_first (?)
			}
		}

		// Uppers flag:  Require >= 1 uc char
		if (opts.uppers) {
			if ((randdig() < 2)
				&& (passwd.size()==0 || is_digit(passwd.back()) || is_consonant(curr_elem.flags))) {
				std::transform(curr_elem.str.begin(),curr_elem.str.end(),curr_elem.str.begin(),::toupper);
				curr_pw_features.has_upper = true;
			}
		}

		// Digits flag:  Require >= 1 digit
		// If curr_elem can go first, maybe append a digit before appending curr_elem.  
		if (opts.digits) {
			if ((randdig()<3) 
				&& passwd.size() > 0 && !is_digit(passwd.back())) {
				//passwd += rand_char(pw_digits);
				std::sample(pw_digits.begin(),pw_digits.end(),std::back_inserter(passwd),1,re);
				curr_pw_features.has_digit = true;
			}
		}

		// Symbols flag:  Require >= 1 symbol
		// If curr_elem can go first, maybe append a symbol before appending curr_elem.  
		if (opts.symbols) {
			if ((randdig()<2) && may_appear_first(curr_elem.flags)) {
				//passwd += rand_char(pw_symbols);
				std::sample(pw_symbols.begin(),pw_symbols.end(),std::back_inserter(passwd),1,re);
				curr_pw_features.has_symbol = true;
			}
		}

		passwd += curr_elem.str;

		prev_elem = curr_elem;

		if (passwd.size() == opts.pw_length) {
			if ((opts.uppers && !curr_pw_features.has_upper) 
				|| (opts.digits && !curr_pw_features.has_digit) 
				|| (opts.symbols && !curr_pw_features.has_symbol)) {
				// The current passwd is the correct length but does not have all the 
				// features required by opts; restart


				if (opts.uppers && !curr_pw_features.has_upper) { ++nfail.upper; }
				if (opts.digits && !curr_pw_features.has_digit) { ++nfail.digit; }
				if (opts.symbols && !curr_pw_features.has_symbol) { ++nfail.symbol; }


				passwd.clear();
				curr_pw_features = passwd_features_t {};
			}
		} else if (passwd.size() > opts.pw_length) {
			++nfail.length;
			passwd.clear();
			curr_pw_features = passwd_features_t {};
		}
	}  // Generate next curr_elem
	
	return passwd;
}



	//auto rand_char = [&re](const std::string& s) -> char {
	//	if (s.size() == 0) {
	//		std::abort();
	//	}
	//	std::uniform_int_distribution rd(0,static_cast<int>(s.size())-1);
	//	return s[rd(re)];
	//};
	//auto rand_elem = [&re]() -> pw_element {
	//	std::uniform_int_distribution rd(0,static_cast<int>(elements.size())-1);
	//	return elements[rd(re)];
	//};





/*
namespace tso {


//
//  Flags for the pw_element
//
#define CONSONANT	0x0001
#define VOWEL		0x0002
#define DIPTHONG	0x0004
#define NOT_FIRST	0x0008

//
// Flags for the pwgen function
//
#define PW_DIGITS	0x0001	// At least one digit 
#define PW_UPPERS	0x0002	// At least one upper letter 
#define PW_SYMBOLS	0x0004
#define PW_AMBIGUOUS	0x0008
#define PW_NO_VOWELS	0x0010

#define NUM_ELEMENTS (sizeof(elements) / sizeof (struct pw_element))

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
		// * OK, we found an element which matches our criteria,
		// * let's do it!
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
}

};  // namespace tso

*/






