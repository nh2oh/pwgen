//
// pw_rand.c --- generate completely random (and hard to remember)
//
//
// Copyright (C) 2001,2002 by Theodore Ts'o
//
// This file may be distributed under the terms of the GNU Public
// License.
//

#include <string>
#include <algorithm>
#include <random>
#include <iostream>
#include "pwgen.h"

const std::string pw_digits {"0123456789"};
const std::string pw_uppers {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
const std::string pw_lowers {"abcdefghijklmnopqrstuvwxyz"};
const std::string pw_symbols {"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"};
const std::string pw_ambiguous {"B8G6I1l0OQDS5Z2"};
const std::string pw_vowels {"01aeiouyAEIOUY"};



std::string pw_rand(const pw_opts_t& opts) {
	std::string drop_chars {};
	drop_chars.reserve(opts.remove_chars.size()+pw_ambiguous.size()+pw_vowels.size());
	drop_chars += opts.remove_chars;
	if (opts.no_ambiguous) { drop_chars += pw_ambiguous; }
	if (opts.no_vowels) { drop_chars += pw_vowels; }

	std::string chars {};
	
	chars += pw_lowers;
	if (opts.digits) {
		std::string digits {};
		std::set_difference(pw_digits.begin(),pw_digits.end(),
		drop_chars.begin(),drop_chars.end(),
		std::back_inserter(digits));

		if (digits.size() == 0) {
			std::cerr << "Error: No digits left in the valid set\n" << std::endl;
			std::abort();
		}
		chars += digits;
	}
	if (opts.uppers) {
		std::string uppers {};
		std::set_difference(pw_uppers.begin(),pw_uppers.end(),
		drop_chars.begin(),drop_chars.end(),
		std::back_inserter(uppers));

		if (uppers.size() == 0) {
			std::cerr << "Error: No uppers left in the valid set\n" << std::endl;
			std::abort();
		}
		chars += uppers;
	}
	if (opts.symbols) {
		std::string symbols {};
		std::set_difference(pw_symbols.begin(),pw_symbols.end(),
		drop_chars.begin(),drop_chars.end(),
		std::back_inserter(symbols));

		if (symbols.size() == 0) {
			std::cerr << "Error: No symbols left in the valid set\n" << std::endl;
			std::abort();
		}
		chars += symbols;
	}

	auto contains = [](const std::string& hstk, const char ndl) -> bool {
		return (std::find(hstk.begin(),hstk.end(),ndl) != pw_digits.end());
	};

	std::default_random_engine re {};
	std::uniform_int_distribution rd {size_t {0}, chars.size()-1};

	std::string passwd {};  passwd.reserve(opts.pw_length);
	bool has_digit {false}; bool has_symbol {false}; bool has_upper {false};
	while (passwd.size() < opts.pw_length) {
		char curr_ch = chars[rd(re)];
		passwd += curr_ch;

		if (!has_digit && opts.digits) {
			has_digit |= contains(pw_digits,curr_ch);
		}
		if (!has_upper && opts.digits) {
			has_upper |= contains(pw_uppers,curr_ch);
		}
		if (!has_symbol && opts.symbols) {
			has_symbol |= contains(pw_symbols,curr_ch);
		}
	
		if (passwd.size() == opts.pw_length) {
			if ((!has_symbol && opts.symbols)
				|| (!has_upper && opts.digits)
				|| (!has_digit && opts.digits)) {
				// passwd is the right length but one or more of the char-inclusion requirements
				// is not set.  
				passwd.clear();
			}
		}
	}

	return passwd;
}



/*
void pw_rand(char *buf, int size, int pw_flags, char *remove)
{
	char		ch, *chars, *wchars;
	int		i, len, feature_flags;

	len = 0;
	if (pw_flags & PW_DIGITS) {
		len += strlen(pw_digits);
	}
	if (pw_flags & PW_UPPERS) {
		len += strlen(pw_uppers);
	}
	len += strlen(pw_lowers);
	if (pw_flags & PW_SYMBOLS) {
		len += strlen(pw_symbols);
	}
		chars = malloc(len+1);
		if (!chars) {
		fprintf(stderr, "Couldn't malloc pw_rand buffer.\n");
		exit(1);
	}
	wchars = chars;
	if (pw_flags & PW_DIGITS) {
		strcpy(wchars, pw_digits);
		wchars += strlen(pw_digits);
	}
	if (pw_flags & PW_UPPERS) {
		strcpy(wchars, pw_uppers);
		wchars += strlen(pw_uppers);
	}
	strcpy(wchars, pw_lowers);
	wchars += strlen(pw_lowers);
	if (pw_flags & PW_SYMBOLS) {
		strcpy(wchars, pw_symbols);
	}
	if (remove) {
		if (pw_flags & PW_AMBIGUOUS)
			remove_chars(chars, pw_ambiguous);
		if (pw_flags & PW_NO_VOWELS)
			remove_chars(chars, pw_vowels);
		remove_chars(chars, remove);
		if ((pw_flags & PW_DIGITS) &&
			!find_chars(chars, pw_digits)) {
			fprintf(stderr,
				"Error: No digits left in the valid set\n");
			exit(1);
		}
		if ((pw_flags & PW_UPPERS) &&
			!find_chars(chars, pw_uppers)) {
			fprintf(stderr,
				"Error: No upper case letters left in "
				"the valid set\n");
			exit(1);
		}
		if ((pw_flags & PW_SYMBOLS) &&
			!find_chars(chars, pw_symbols)) {
			fprintf(stderr,
				"Error: No symbols left in the valid set\n");
			exit(1);
		}
		if (chars[0] == '\0') {
			fprintf(stderr,
				"Error: No characters left in the valid set\n");
			exit(1);
		}
	}
	len = strlen(chars);
try_again:
	feature_flags = (size > 2) ? pw_flags : 0;
	i = 0;
	while (i < size) {
		ch = chars[pw_number(len)];
		if ((pw_flags & PW_AMBIGUOUS) && strchr(pw_ambiguous,ch))
			continue;
		if ((pw_flags & PW_NO_VOWELS) && strchr(pw_vowels, ch))
			continue;
		buf[i++] = ch;
		if ((feature_flags & PW_DIGITS) &&
			strchr(pw_digits, ch))
			feature_flags &= ~PW_DIGITS;
		if ((feature_flags & PW_UPPERS) &&
			strchr(pw_uppers, ch))
			feature_flags &= ~PW_UPPERS;
		if ((feature_flags & PW_SYMBOLS) &&
			strchr(pw_symbols, ch))
			feature_flags &= ~PW_SYMBOLS;
	}
	if (feature_flags & (PW_UPPERS | PW_DIGITS | PW_SYMBOLS))
		goto try_again;
	buf[size] = 0;
	free(chars);
	return;
}	
*/

