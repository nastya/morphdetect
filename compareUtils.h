#ifndef __COMPARE_UTILS_H
#define __COMPARE_UTILS_H

#include "timer.h"
#include <iostream>
#include <algorithm>
#include <unordered_map>
using namespace std;

typedef uint8_t mbyte;
typedef uint32_t mblock;

class CompareUtils {
public:
	static size_t cleanup(mbyte *dst, const mbyte *src, size_t src_len);
	static size_t compare_simple(unordered_map<mblock, size_t> &sample_stat, const mbyte* model, size_t model_size);
	static size_t best_match_simple(const mbyte *sample, size_t sample_size, const mbyte **models, const int *model_sizes, int models_count, float threshold, float *coef_out = NULL, float *ans_out = NULL);
	static size_t compare_diff(const mbyte *sample, size_t sample_size, const mbyte *model, size_t model_size, float threshold);
	static bool possible_diff(const mbyte *sample, size_t sample_size, const mbyte *model, size_t model_size, float threshold);
	static size_t best_match(const mbyte *sample, size_t sample_size, const mbyte **models, const int *model_sizes, int models_count, float threshold, float *coef_out = NULL, float *ans_out = NULL);

	template<class T> static int best_match(T &sample, T* models, int models_count, float threshold, float *coef_out = NULL, float *ans_out = NULL)
	{
		TimerAnalyzer::start(TimeDiff);

		float max_coef = 0;
		int max_ans = 0, ind_max = 0;

		unordered_map<uint64_t, uint32_t> stat_sample;
		for (auto &x : sample)
			stat_sample[x.hash]++;

		for (int i = 0; i < models_count; i++)
		{
			int ans;
			float coef = compare_diff(stat_sample, sample, models[i], threshold, &ans);
			if (coef > max_coef)
			{
				max_coef = coef;
			}
			if (ans > max_ans)
			{
				max_ans = ans;
				ind_max = i;
			}
		}

		if (ans_out != NULL)
			*ans_out = max_ans;

		if (coef_out != NULL)
			*coef_out = max_coef;

		TimerAnalyzer::stop(TimeDiff);
		return (max_coef > threshold) ? ind_max : -1;
	}

	template<class T> static inline bool possible_diff(unordered_map<uint64_t, uint32_t> &stat_sample, T &model, float required)
	{
		int total;

		total = 0;
		for (auto &x : model)
			total += stat_sample.count(x.hash);
		if (total < required)
			return false;

		unordered_map<uint64_t, uint32_t> stat_model;
		for (auto &x : model)
			stat_model[x.hash]++;

		total = 0;
		for (auto &pair : stat_model)
			total += min(pair.second, stat_sample[pair.first]);
		if (total < required)
			return false;

		return true;
	}

	template<class T> static float compare_diff(unordered_map<uint64_t, uint32_t> &stat_sample, T &sample, T &model, float threshold, int *ans_out = NULL)
	{
		int ans = 0;

		if (possible_diff(stat_sample, model, model.size() * threshold))
			ans = longest_common_subsequence(sample, model);

		float coef = ans * 1.0 / model.size();

		if (ans_out != NULL)
			*ans_out = ans;

		return coef;
	}

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
