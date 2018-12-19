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
#include<array>


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

enum eflag {
	none = 0x0000,
	is_consonant = 0x0001,
	is_vowel = 0x0002,
	is_dipthong = 0x0004,
	not_first = 0x0008
};
//operator eflag(int) { return static_cast<eflag


enum class rqflag {
	vowel = 0,
	dipthong = 1,
	first = 2
};
enum class rqflag_forbid {
	vowel = 0,
	dipthong = 1,
	first = 2
};
constexpr rqflag_forbid operator ~(rqflag f) {
	return static_cast<rqflag_forbid>(static_cast<int>(f));
};
class elem_rq {
public:
	// Setters
	void reset() { std::fill(this->rq_.begin(),this->rq_.end(),0); };
	constexpr elem_rq& operator &=(int) { return *this;};
	constexpr elem_rq& operator &=(rqflag f) { this->rq_[static_cast<size_t>(f)] = 1; return *this;};
	constexpr elem_rq& operator &=(rqflag_forbid f) { this->rq_[static_cast<size_t>(f)] = -1; return *this; };

	// Getters
	constexpr bool operator &&(int f) const { 
		if ((f & eflag::is_consonant) && (this->rq_[static_cast<size_t>(rqflag::vowel)]==1)) {
			return false;
		}
		if ((f &~ eflag::is_consonant) && (this->rq_[static_cast<size_t>(rqflag::vowel)]==-1)) {
			return false;
		}
		if ((f & eflag::is_vowel) && (this->rq_[static_cast<size_t>(rqflag::vowel)]==-1)) {
			return false;
		}
		if ((f &~ eflag::is_vowel) && (this->rq_[static_cast<size_t>(rqflag::vowel)]==1)) {
			return false;
		}
		if ((f & eflag::is_dipthong) && (this->rq_[static_cast<size_t>(rqflag::dipthong)]==-1)) {
			return false;
		}
		if ((f &~ eflag::is_dipthong) && (this->rq_[static_cast<size_t>(rqflag::dipthong)]==1)) {
			return false;
		}
		if ((f & eflag::not_first) && (this->rq_[static_cast<size_t>(rqflag::first)]==1)) {
			return false;
		}
		if ((f &~ eflag::not_first) && (this->rq_[static_cast<size_t>(rqflag::first)]==-1)) {
			return false;
		}
		return true;
	};

	constexpr bool operator &&(rqflag f) const { 
		return this->rq_[static_cast<size_t>(f)] == 1;
	};
	constexpr bool operator &&(rqflag_forbid f) const { 
		return this->rq_[static_cast<size_t>(f)] == -1;
	};
private:
	std::array<int,3> rq_ {0,0,0};
};


/*
class elem_properties_t {
public:
	enum mode {
		require = 0x0001,
		forbid = 0x0002,
		ignore = 0x0004
	};
	enum class flag {
		vowel = 0x0002,
		dipthong = 0x0004,
		not_first = 0x0008
	};
	// TODO:  Define:
	// flagset ~ int
	// bool operator==(flagset,flag) const;  bool operator!=(flagset,flag) const;
	// flagset operator&(flagset,flag) const;  flagset operator|(flagset,flag) const;
	// flagset operator(flag);

	explicit elem_properties_t()=default;

	// Getters
	bool satisfied(elem_properties_t::flag f, bool contains) const {
		int flgmode = m_prop[f2idx(f)];
		return ((flgmode==0) || (contains && flgmode==1) || (!contains && flgmode==-1));
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
	// Replace above w/ :  
	// set_requires(flag,bool)
	// set_forbid(flag,bool)
	// set_ignore(flag,bool)

	void set(elem_properties_t::flag f, elem_properties_t::mode m) {
		m_prop[f2idx(f)] = m;
	};

	void reset() { std::fill(m_prop.begin(),m_prop.end(),ignore); };
private:
	int f2idx(elem_properties_t::flag f) const {
		if (f == elem_properties_t::flag::vowel) { return 0; };
		if (f == elem_properties_t::flag::dipthong) { return 1; };
		if (f == elem_properties_t::flag::not_first) { return 2; };
	};
	std::array<elem_properties_t::mode,3> m_prop {ignore,ignore,ignore};
};*/

struct pw_element {
	std::string str;
	//const char *str;
	//eflag flags;
	int flags;
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


extern const char *pw_symbols;
extern const char *pw_ambiguous;

// sha1num.c //
void pw_sha1_init(char *sha1);
int pw_sha1_number(int max_num);



