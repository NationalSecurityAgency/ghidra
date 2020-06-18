/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.file.formats.android.oat;

/**
 * https://android.googlesource.com/platform/art/+/master/runtime/index_bss_mapping.h
 *
 */
public final class IndexBssUtilities {

	public final static int indexMask(int index_bits) {
		int kAllOnes = -1;
		// Handle `index_bits == 32u` explicitly; shifting uint32_t left by 32 is undefined behavior.
		return (index_bits == 32) ? kAllOnes : ~(kAllOnes << index_bits);
	}

	public final static int intIndexBits(int number_of_indexes) {
		return minimumBitsToStore(number_of_indexes - 1);
	}

	private static int minimumBitsToStore(int value) {
		return 0;
	}

}
