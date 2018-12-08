#pragma once
/*
 * pwgen.h --- header file for password generator
 *
 * Copyright (C) 2001,2002 by Theodore Ts'o
 * 
 * This file may be distributed under the terms of the GNU Public
 * License.
 */
#include <string>
#include <vector>

struct pw_opts_t {
	bool digits {true};  // True => at least one digit
	bool uppers {true};  // True => At least one uppercase letter
	bool symbols {false};
	bool no_vowels {false};  // Don't use vowels:  -v | --no-vowels
	bool no_ambiguous {false};  // "Don't include ambiguous characters":  -B | --ambiguos
	bool random {false};  // "generate completely random passwords -s | --secure"
		// use pwgen = pw_rand
	bool cols {true};  // output in cols:  -C
	int num_cols {1};
	int num_pw {5};  // number of pw's to generate
	int pw_length {10};
	std::string remove_chars {};
	int flags {0};  // not sure how to init for optflags enum
};

std::string pw_phonemes(const pw_opts_t&);
std::string pw_rand(const pw_opts_t&);

enum class eflag {
	is_consonant 0x0001,
	is_vowel 0x0002,
	is_dipthong 0x0004,
	not_first 0x0008
};

enum class optflag {
	require_digits 0x0001,
	require_uppers 0x0002,
	require_symbols 0x0004,
	no_ambiguous 0x0008,
	no_vowels 0x0010
};

struct pw_element {
	const char	*str;
	eflag flags;
};

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

// pointer to choose between random or sha1 pseudo random number generator //
//extern int (*pw_number)(int max_num);

extern const char *pw_symbols;
extern const char *pw_ambiguous;

// Function prototypes //

// pw_phonemes.c//
//extern void pw_phonemes(char *buf, int size, int pw_flags, char *remove);

// pw_rand.c //
//extern void pw_rand(char *buf, int size, int pw_flags, char *remove);

// randnum.c //
//extern int pw_random_number(int max_num);

// sha1num.c //
extern void pw_sha1_init(char *sha1);
extern int pw_sha1_number(int max_num);
