#include "instructionQueue.h"
#include "compareUtils.h"

InstructionQueue::InstructionQueue()
 : vector<InstructionInfo>()
{
}

void InstructionQueue::statCheck()
{
	if (_stat.empty())
		statFill();
}

void InstructionQueue::statFill()
{
	_stat.clear();
	for (auto &x : *this)
		_stat[x.hash]++;
}


int InstructionQueue::bestMatch(InstructionQueue *models, int models_count, float threshold, float *coef_out, float *ans_out)
{
	TimerAnalyzer::start(TimeMatch);

	float max_coef = 0;
	int max_ans = 0, ind_max = 0;

	for (int i = 0; i < models_count; i++)
	{
		int ans;
		float coef = diff(models[i], threshold, &ans);
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

	TimerAnalyzer::stop(TimeMatch);
	return (max_coef > threshold) ? ind_max : -1;
}

float InstructionQueue::diff(InstructionQueue &model, float threshold, int *ans_out)
{
	int ans = 0;

	if (diffPossible(model, threshold))
		ans = CompareUtils::longest_common_subsequence(*this, model);

	float coef = ans * 1.0 / model.size();

	if (ans_out != NULL)
		*ans_out = ans;

	return coef;
}


bool InstructionQueue::diffPossible(InstructionQueue &model, float required)
{
	required *= model.size();
	statCheck();
	model.statCheck();

	int total;

	total = 0;
	for (auto &pair : model._stat)
		total += pair.second * _stat.count(pair.first);
	if (total < required)
		return false;

	total = 0;
	for (auto &pair : model._stat)
		total += min(pair.second, _stat[pair.first]);
	if (total < required)
		return false;

	return true;
}
