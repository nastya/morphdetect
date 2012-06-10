#ifndef __COMPARE_UTILS_H
#define __COMPARE_UTILS_H

#include "timer.h"
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include "sample.h"
using namespace std;

typedef uint8_t mbyte;
typedef uint32_t mblock;

class CompareUtils {
public:
	static size_t cleanup(mbyte *dst, const mbyte *src, size_t src_len);
	static size_t compare_simple(unordered_map<mblock, size_t> &sample_stat, Sample &shellcode);
	static size_t best_match_simple(MemoryBlock &sample, vector<Sample> &shellcodes, float threshold, float *coef_out = NULL, float *ans_out = NULL);
	static size_t compare_diff(MemoryBlock &sample, Sample &shellcode, float threshold);
	static bool possible_diff(const mbyte *sample, size_t sample_size, Sample &shellcode, float threshold);
	static size_t best_match(MemoryBlock &sample, vector<Sample> &shellcodes, float threshold, float *coef_out = NULL, float *ans_out = NULL);

	template<class T1, class T2> static inline size_t longest_common_subsequence(T1 &s1, T2 &s2)
	{
		return longest_common_subsequence_ref(s1, s1.size(), s2, s2.size());
	}

	template<class T1, class T2> static inline size_t longest_common_subsequence(T1 s1, size_t len1, T2 s2, size_t len2)
	{
		return longest_common_subsequence_ref(s1, len1, s2, len2);
	}

	template<class T1, class T2> static size_t longest_common_subsequence_ref(T1 &s1, size_t len1, T2 &s2, size_t len2)
	{
		if ((len1 == 0) || (len2 == 0)) {
			cerr << "WHOOPS! " << len1 << " " << len2 << endl;
			return 0;
		}

		TimerAnalyzer::start(TimeLCS);

		size_t f[len1][len2];
		for (size_t i = 0; i < len1; i++)
		{
			f[i][0] = 0;
		}
		for (size_t i = 0; i < len2; i++)
		{
			f[0][i] = 0;
		}

		for (size_t i = 1; i < len1; i++)
		{
			for (size_t j = 1; j < len2; j++)
			{
				if (s1[i] == s2[j])
					f[i][j] = f[i - 1][j - 1] + 1;
				else
					f[i][j] = max(f[i][j - 1], f[i - 1][j]);
			}
		}

		TimerAnalyzer::stop(TimeLCS);
		return f[len1 - 1][len2 - 1];
	}
};

#endif //__COMPARE_UTILS_H
