#pragma once
// pwgen.h --- header file for password generator
// Copyright (C) 2018 by Ben Knowles
// Copyright (C) 2001,2002 by Theodore Ts'o
// This file may be distributed under the terms of the GNU Public License.
//
#include <string>


enum eflag {
	vowel = 0x0001,
	dipthong = 0x0004,
	first = 0x0008
};

struct pw_element {
	std::string str {};
	int flags {0};
};

struct pw_opts_t {
	bool digits {true};  // True => at least one digit
	bool uppers {true};  // True => At least one uppercase letter
	bool symbols {false};  // True => at least one symbol
	bool no_vowels {false};  // Don't use vowels:  -v | --no-vowels
	bool no_ambiguous {false};  // "Don't include ambiguous characters":  -B | --ambiguos
	bool random {false};  // "generate completely random passwords -s | --secure"
		// use pwgen = pw_rand
	bool cols {true};  // output in cols:  -C
	int num_cols {1};
	int num_pw {5};  // number of pw's to generate
	int pw_length {10};
	std::string remove_chars {};
};
std::string pw_phonemes(const pw_opts_t&);
std::string pw_rand(const pw_opts_t&);

std::string usage();  // Prints usage info


/*
//Flags for the pw_element
#define CONSONANT	0x0001
#define VOWEL		0x0002
#define DIPTHONG	0x0004
#define NOT_FIRST	0x0008
//Flags for the pwgen function
#define PW_DIGITS	0x0001	// At least one digit
#define PW_UPPERS	0x0002	// At least one upper letter
#define PW_SYMBOLS	0x0004
#define PW_AMBIGUOUS	0x0008
#define PW_NO_VOWELS	0x0010
*/


extern const char *pw_symbols;
extern const char *pw_ambiguous;

// sha1num.c //
void pw_sha1_init(char *sha1);
int pw_sha1_number(int max_num);



