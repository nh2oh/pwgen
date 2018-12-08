/*
 * pw_rand.c --- generate completely random (and hard to remember)
 * 	passwords
 *
 * Copyright (C) 2001,2002 by Theodore Ts'o
 * 
 * This file may be distributed under the terms of the GNU Public
 * License.
 */

#include <string>
#include <algorithm>
#include <random>
#include "pwgen.h"

const char *pw_digits = "0123456789";
const char *pw_uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char *pw_lowers = "abcdefghijklmnopqrstuvwxyz";
const char *pw_symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const char *pw_ambiguous = "B8G6I1l0OQDS5Z2";
const char *pw_vowels = "01aeiouyAEIOUY";



std::string pw_rand(const pw_opts_t& opts) {
	std::string chars {};
	chars += pw_lowers;_
	if (opts.digits) { chars += pw_digits; }  
	if (opts.uppers) { chars += pw_uppers; }
	if (opts.symbols) { chars += pw_symbols; }
	// should first build drop_chars then call set_diff in each of these

	std::string drop_chars {};
	drop_chars += opts.remove_chars;
	if (opts.no_ambiguous) { drop_chars += pw_ambiguous; }
	if (opts.no_vowels) { drop_chars += pw_vowels; }
	
	std::string final_chars {};
	std::set_difference(chars.begin(),chars.end(),
		drop_chars.begin(),drop_chars.end(),
		final_chars.begin());

	// check to make sure remove_chars did not remove all the digits
	if (opts.digits 
		&& std::search(chars.begin(),chars.end(),pw_digits.begin(),pw_digits.end()) == chars.end()) {
		std::cerr << "Error: No digits left in the valid set\n" << std::endl;
		std::abort();
	}
	if (opts.uppers 
		&& std::search(chars.begin(),chars.end(),pw_uppers.begin(),pw_uppers.end()) == chars.end()) {
		std::cerr << "Error: No uppers left in the valid set\n" << std::endl;
		std::abort();
	}
	if (opts.symbols 
		&& std::search(chars.begin(),chars.end(),pw_symbols.begin(),pw_symbols.end()) == chars.end()) {
		std::cerr << "Error: No symbols left in the valid set\n" << std::endl;
		std::abort();
	}
	if (chars.size() == 0) {
		std::cerr << "Error: No chars left in the valid set\n" << std::endl;
		std::abort();
	}

	std::default_random_engine re {};
	std::uniform_int_distribution rd {0, chars_final.size()-1};

	std::string passwd {};
	optflag passwd_satisfies {};  // Not sure how to default-construct
	while (passwd.size() < opts.pw_length) {
		char curr_ch = chars_final[rd(re)];
		passwd += curr_ch;

		if ((passwd_satisfies & optflag::require_digits) &&
			std::find(pw_digits.begin(),pw_digits.end(),ch) != pw_digits.end()) {
			passwd_satisfies &= ~optflag::require_digits;
		}
		if ((passwd_satisfies & optflag::require_uppers) &&
			std::find(pw_uppers.begin(),pw_uppers.end(),ch) != pw_uppers.end()) {
			passwd_satisfies &= ~optflag::require_uppers;
		}
		if ((passwd_satisfies & optflag::require_symbols) &&
			std::find(pw_symbols.begin(),pw_symbols.end(),ch) != pw_symbols.end()) {
			passwd_satisfies &= ~optflag::require_symbols;
		}
	
		if (passwd_satisfies & (optflag::require_uppers | optflag::require_digits | optflag::require_symbols)) {
			passwd.clear();
			// passwd_satisfies = ... need to clear ...
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

