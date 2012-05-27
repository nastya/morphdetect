#include "compareUtils.h"

size_t CompareUtils::cleanup(mbyte *dst, const mbyte *src, size_t src_len) {
	size_t dst_size = 0;
	for (size_t i = 0; i < src_len; i++) {
		switch (src[i]) {
			case 0x0: // null
			case 0x90: // nop
				continue;
		}
		if (dst != NULL) {
			dst[dst_size] = src[i];
		}
		dst_size++;
	}
	return dst_size;
}

size_t CompareUtils::compare_simple(unordered_map<mblock, size_t> &sample_stat, const mbyte* model, size_t model_size)
{
	unordered_map<mblock, size_t> model_stat;
	const mbyte *b = model;
	for (size_t i = 0; i <= model_size - sizeof(mblock); i++, b++)
		model_stat[*(const mblock *) b]++;

	size_t count = 0;
	for (auto &pair : model_stat)
		count += min(pair.second, sample_stat[pair.first]);
	return count;
}

size_t CompareUtils::best_match_simple(const mbyte *sample, size_t sample_size, const mbyte **models, const int *model_sizes, int models_count, float threshold, float *coef_out, float *ans_out)
{
	TimerAnalyzer::start(TimeDiff);
	float max_coef = 0;
	int max_ans = 0, ind_max = 0;

	unordered_map<mblock, size_t> sample_stat;
	const mbyte *b = sample;
	for (size_t i = 0; i <= sample_size - sizeof(mblock); i++, b++)
		sample_stat[*(const mblock *) b]++;

	for (int i = 0; i < models_count; i++)
	{
		int ans = compare_simple(sample_stat, models[i], model_sizes[i]);
		float coef = ans * 1.0 / model_sizes[i];
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

size_t CompareUtils::compare_diff(const mbyte *sample, size_t sample_size, const mbyte *model, size_t model_size, float threshold)
{
	if ((model_size == 0) || (sample_size == 0)) {
		cerr << "WHOOPS! " << model_size << " " << sample_size << endl;
		return 0;
	}
	size_t step_size = model_size * 2;
	if (sample_size <= 2 * step_size) {
		if (!possible_diff(sample, sample_size, model, model_size, threshold))
			return 0;
		return longest_common_subsequence(sample, sample_size, model, model_size);
	}
	size_t last = sample_size - 2 * step_size;

	size_t res = 0;
	for (size_t i = 0; i < sample_size - step_size; i += step_size) {
		const mbyte *data = sample + min(i, last);
		size_t data_size = 2 * step_size;
		if (!possible_diff(data, data_size, model, model_size, threshold))
			continue;
		res = max(res, longest_common_subsequence(data, data_size, model, model_size));
	}
	return res;
}

bool CompareUtils::possible_diff(const mbyte *sample, size_t sample_size, const mbyte *model, size_t model_size, float threshold)
{
	uint32_t stat_sample[256] = {0}, stat_model[256] = {0};

	for (size_t i = 0; i < sample_size; i++)
		stat_sample[sample[i]]++;
	for (size_t i = 0; i < model_size; i++)
		stat_model[model[i]]++;

	int total = 0;
	for (size_t i = 0; i < 256; i++)
		total += min(stat_model[i], stat_sample[i]);

	return total >= threshold * model_size;
}

size_t CompareUtils::best_match(const mbyte *sample, size_t sample_size, const mbyte **models, const int *model_sizes, int models_count, float threshold, float *coef_out, float *ans_out)
{
	TimerAnalyzer::start(TimeDiff);
	float max_coef = 0;
	int max_ans = 0, ind_max = 0;

	for (int i = 0; i < models_count; i++)
	{
		int ans = compare_diff(sample, sample_size, models[i], model_sizes[i], threshold);
		float coef = ans * 1.0 / model_sizes[i];
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

