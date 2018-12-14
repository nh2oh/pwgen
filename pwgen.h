#pragma once
// pwgen.h --- header file for password generator
// Copyright (C) 2018 by Ben Knowles
// Copyright (C) 2001,2002 by Theodore Ts'o
// This file may be distributed under the terms of the GNU Public License.
//
#include <string>
#include <vector>
#include <bitset>
#include <algorithm>

// Returns usage info
std::string usage();

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

enum class eflag {
	none = 0x0000,
	is_consonant = 0x0001,
	is_vowel = 0x0002,
	is_dipthong = 0x0004,
	not_first = 0x0008
};

class elem_properties_t {
public:
	enum mode {
		require = 0x0001,
		forbid = 0x0002,
		ignore = 0x0004
	};
	enum flag {
		vowel = 0x0002,
		dipthong = 0x0004,
		not_first = 0x0008
	};

	explicit elem_properties_t()=default;

	// Getters
	bool satisfied(elem_properties_t::flag f, bool contains) const {
		int flgmode = m_prop[f2idx(f)];
		return ((flgmode==0) || (contains && flgmode==1) || (!contains && flgmode==-1))
	};
	bool requires(elem_properties_t::flag f) const {
		return m_prop[f2idx(f)]==1;
	};
	bool forbids(elem_properties_t::flag f) const {
		return m_prop[f2idx(f)]==-1;
	};
	bool ignores(elem_properties_t::flag f) const {
		return m_prop[f2idx(f)]==0;
	};

	// Setters
	void set(elem_properties_t::flag f, bool rqf) {
		rqf ? set(f,elem_properties_t::mode::require) : set(f,elem_properties_t::mode::forbid);
	};

	void set(elem_properties_t::flag f, elem_properties_t::mode m) {
		int v {0};
		if (m==elem_properties_t::mode::forbid) {
			v = -1;
		} else if (m==elem_properties_t::mode::require) {
			v = 1;
		else if (m==elem_properties_t::mode::ignore) {
			v = 0;
		}
		m_prop[f2idx(f)] = v;
	};

	void reset() { std::fill(m_prop.begin(),m_prop.end(),0); };
private:
	int f2idx(elem_properties_t::flag f) const {
		if (f == elem_properties_t::flag::vowel) { return 0; };
		if (f == elem_properties_t::flag::dipthong) { return 1; };
		if (f == elem_properties_t::flag::not_first) { return 2; };
	};
	std::array<int,4> m_prop {0,0,0,0};
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

// sha1num.c //
extern void pw_sha1_init(char *sha1);
extern int pw_sha1_number(int max_num);
