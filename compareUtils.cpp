#include "compareUtils.h"

namespace detect_similar
{

/**
 * Copies bytes from src to dst ignoring 0x0 and 0x90
 */

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

} //namespace detect_similar
