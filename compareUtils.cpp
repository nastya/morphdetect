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

size_t CompareUtils::compare_simple(const mbyte* d1, size_t d1_size, const mbyte* d2, size_t d2_size)
{
	const mbyte *b1, *b2 = d2;
	size_t count = 0;
	for (size_t i2 = 0; i2 <= d2_size - sizeof(mblock); i2++, b2++) {
		b1 = d1;
		for (size_t i1 = 0; i1 <= d1_size - sizeof(mblock); i1++, b1++) {
			if (*(const mblock *)b1 == *(const mblock *)b2) {
				count++;
				break;
			}
		}
	}
	return count;
}

size_t CompareUtils::compare_diff(const mbyte *signature, size_t signature_size, const mbyte *data, size_t data_size)
{
	if ((signature_size == 0) || (data_size == 0)) {
		cerr << "WHOOPS! " << signature_size << " " << data_size << endl;
		return 0;
	}
	size_t step_size = signature_size * 2;
	if (data_size <= 2 * step_size) {
		return longest_common_subsequence(signature, signature_size, data, data_size);
	}
	size_t last = data_size - 2 * step_size;

	size_t res = 0;
	for (size_t i = 0; i < data_size - step_size; i += step_size) {
		res = max(res, longest_common_subsequence(signature, signature_size,
							 data + min(i, last), 2 * step_size));
	}
	return res;
}
