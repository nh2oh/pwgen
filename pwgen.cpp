// pwgen.cpp -- generate secure passwords
// Copyright (C) 2018 by Ben Knowles
// Copyright (C) 2001,2002 by Theodore Ts'o
// This file may be distributed under the terms of the GNU Public License.
//

#include "pwgen.h"
#include <iostream>
#include <string>
#include <algorithm>  // std::max()
#include <exception>

std::string usage();

int main(int argc, char **argv) {
	int	term_width = 80;
	const char *pw_options = "01AaBCcnN:sr:hH:vy";

	if (isatty(1)) { do_columns = 1; }
	optflag pwgen_flags {optflag::require_digits | optflag::require_uppers};

	pw_opts_t opts {};
	// Parse cmd ln:
	// 1)  Set pw_opts (pwgen_flags); includes do_columns, pw_number, num_pw,
	//     char* remove (opts.remove_chars for opt 'r')
	// 2)  Set pwgen == pw_rand (opt v, r, s)
	//     Default pwgen == pw_phonemes
	// 3)  Set pw_number; opt H => pw_number == pw_sha1_number(); pw_sha1_init() opt H
	//     Default pw_number == pw_random_number
	// 4)  Call usage() if unrecognized arg

	if (opts.pw_length < 5) {
		opts.random = true;
	}
	if (!opts.random) {
		if (opts.pw_length <= 2) { opts.uppers = false; }  // pwgen_flags &= ~PW_UPPERS;
		if (opts.pw_length <= 1) { opts.digits = false; }  // pwgen_flags &= ~PW_DIGITS;
		// Not sure why not allowed to have uppers in 2-char pw's, or digits in 1-char pw's.
		// Do i not understand this correctly?
	}
	if (opts.pw_length <= 0) {
		std::cerr << "Invalid password length.  \n" << std::endl;
		return -1;
	}
	if (opts.num_pw <= 0) {
		std::cerr << "Invalid number of passwords.  \n" << std::endl;
		return -1;
	}
	if (opts.cols) {
		if (opts.num_cols <= 0) {
			std::cerr << "Invalid number of columns.  \n" << std::endl;
			return -1;
		}
		opts.num_cols = std::max(term_width/(opts.pw_length+1),1);
	}
	//if (num_pw < 0) {num_pw = do_columns ? num_cols * 20 : 1; }
	

	std::string curr_passwd {};
	for (int i=0; i < opts.num_pw; ++i) {
		if (!opts.random) {
			curr_passwd = pw_phonemes(opts);
		} else {
			curr_passwd = pw_rand(opts);
		}

		if (!opts.cols || ((i % opts.num_cols)==(opts.num_cols-1)) || (i==(opts.num_pw-1))) {
			std::cout << curr_passwd << "\n";
		} else {
			std::cout << curr_passwd << "\n";
		}
	}

	return 0;
}


std::string usage() {
	std::string s {};

	s += "Usage: pwgen [ OPTIONS ] [ pw_length ] [ num_pw ]\n\n";
	s += "Options supported by pwgen:\n";
	s += "  -c or --capitalize\n";
	s += "\tInclude at least one capital letter in the password\n";
	s += "  -A or --no-capitalize\n";
	s += "\tDon't include capital letters in the password\n";
	s += "  -n or --numerals\n";
	s += "\tInclude at least one number in the password\n";
	s += "  -0 or --no-numerals\n";
	s += "\tDon't include numbers in the password\n";
	s += "  -y or --symbols\n";
	s += "\tInclude at least one special symbol in the password\n";
	s += "  -r <chars> or --remove-chars=<chars>\n";
	s += "\tRemove characters from the set of characters to generate passwords\n";
	s += "  -s or --secure\n";
	s += "\tGenerate completely random passwords\n";
	s += "  -B or --ambiguous\n";
	s += "\tDon't include ambiguous characters in the password\n";
	s += "  -h or --help\n";
	s += "\tPrint a help message\n";
	s += "  -H or --sha1=path/to/file[#seed]\n";
	s += "\tUse sha1 hash of given file as a (not so) random generator\n";
	s += "  -C\n\tPrint the generated passwords in columns\n";
	s += "  -1\n\tDon't print the generated passwords in columns\n";
	s += "  -v or --no-vowels\n";
	s += "\tDo not use any vowels so as to avoid accidental nasty words\n";
	
	return s;
}

/*pw_opts get_cmdln_opts(const std::vector<std::string>& cmd_ln, const std::string& opts_fmt) {
	
	bool expect_optn_name {false}; bool expect_optn_arg {false};
	for (int i=0; i<cmd_ln.size(); ++i) {
		//...
	}

}*/



