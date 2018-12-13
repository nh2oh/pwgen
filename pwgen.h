#pragma once
// pwgen.h --- header file for password generator
// Copyright (C) 2018 by Ben Knowles
// Copyright (C) 2001,2002 by Theodore Ts'o
// This file may be distributed under the terms of the GNU Public License.
//
#include <string>
#include <vector>
#include <bitset>

// Returns usage info
std::string usage();

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
	none = 0x0000,
	is_consonant = 0x0001,
	is_vowel = 0x0002,
	is_dipthong = 0x0004,
	not_first = 0x0008
};

enum class optflag {
	none = 0x0000,
	require_digits = 0x0001,
	require_uppers = 0x0002,
	require_symbols = 0x0004,
	no_ambiguous = 0x0008,
	no_vowels = 0x0010
};

class elem_properties_t {
public:
	enum flag {
		consonant = 0x0001,
		vowel = 0x0002,
		dipthong = 0x0004,
		not_first = 0x0008
	};
	explicit elem_properties_t()=default;
	/*explicit elem_properties_t(elem_properties_t::flag f) {
		m_prop += f;
		*this->is_consonant(f & elem_properties_t::flag::consonant);
		*this->is_vowel(f & elem_properties_t::flag::vowel);
		*this->is_dipthong(f & elem_properties_t::flag::dipthong);
		*this->not_first(f & elem_properties_t::flag::not_first);
	};*/
	// Getters
	bool consonant() const { return m_prop[0]; };
	bool vowel() const { return m_prop[1]; };
	bool vowel_or_consonant { return m_prop[4]; };  // NB: 4
	bool dipthong() const { return m_prop[2]; };
	bool not_first() const { return m_prop[3]; };
	// Setters
	void consonant(bool on) { m_prop[0] = on; };
	void vowel(bool on) { m_prop[1] = on; };
	bool vowel_or_consonant(bool on) { m_prop[4] = on; };  // NB: 4
    void is_dipthong(bool on) { m_prop[2] = on; };
    void not_first(bool on) { m_prop[3] = on; };

	void reset() { m_prop.reset(); };
private:
	void set(elem_properties_t::flag f) {
		if (f == (elem_properties_t::flag::vowel | elem_properties_t::flag::consonant)) { *this->vowel_or_consonant(true); };
			// Has to be before setter for consonant() & vowel()
		if (f == elem_properties_t::flag::consonant) { *this->consonant(true); };
		if (f == elem_properties_t::flag::vowel) { *this->vowel(true); };
		if (f == elem_properties_t::flag::dipthong) { *this->dipthong(true); };
		if (f == elem_properties_t::flag::not_first) { *this->not_first(true); };
	};
	std::bitset<5> m_prop {0,0,0,0,0};
};

struct pw_element {
	const char	*str;
	eflag flags;
};

class pw_properties_t {
public:
	// Getters
	bool digits() const { return m_prop[0]; };
	bool uppers() const { return m_prop[1]; };
	bool symbols() const { return m_prop[2]; };
	bool no_ambiguous() const { return m_prop[3]; };
	bool no_vowels() const { return m_prop[4]; };
	// Setters
	void digits(bool on) { m_prop[0] = on; };
	void uppers(bool on) { m_prop[1] = on; };
    void symbols(bool on) { m_prop[2] = on; };
    void no_ambiguous(bool on) { m_prop[3] = on; };
	void no_vowels(bool on) { m_prop[4] = on; };
private:
	std::bitset<5> m_prop {0,0,0,0,0};
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
