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
package generic.lsh;

import generic.lsh.vector.HashEntry;

public class Partition {
	private Partition() {
		// non-instantiable class
	}

	private static final int FNV_32_BIT_OFFSET_BASIS = 0x811C9DC5;
	private static final int FNV_32_BIT_PRIME = 0x1000193;

	private static boolean partition(final int identity, final int value) {
		int hash = FNV_32_BIT_OFFSET_BASIS;

		int blender = value;

		hash ^= blender & 0xff;
		hash *= FNV_32_BIT_PRIME;
		blender >>>= 8;
		hash ^= blender & 0xff;
		hash *= FNV_32_BIT_PRIME;
		blender >>>= 8;
		hash ^= blender & 0xff;
		hash *= FNV_32_BIT_PRIME;
		blender >>>= 8;
		hash ^= blender & 0xff;
		hash *= FNV_32_BIT_PRIME;

		blender = identity;

		hash ^= blender & 0xff;
		hash *= FNV_32_BIT_PRIME;
		blender >>>= 8;
		hash ^= blender & 0xff;
		hash *= FNV_32_BIT_PRIME;
		blender >>>= 8;
		hash ^= blender & 0xff;
		hash *= FNV_32_BIT_PRIME;
		blender >>>= 8;
		hash ^= blender & 0xff;
		hash *= FNV_32_BIT_PRIME;

		final int bitCount = Integer.bitCount(hash);
		return bitCount % 2 == 0;
	}

	private static int partition(final int identity, final HashEntry[] values) {
		float total = 0;
		for (int i=0;i<values.length;++i) {
			HashEntry entry = values[i];
			if (partition(identity, entry.getHash()))
				total += entry.getCoeff();
			else
				total -= entry.getCoeff();
		}
		return total < 0 ? 0 : 1;
	}

	public static int hash(final int[] partitionIdentities, final HashEntry[] values) {
		int result = 0;
		int bit = 1;
		for (int identity : partitionIdentities) {
			if (partition(identity, values) == 1) {
				result |= bit;
			}
			bit <<= 1;
		}
		return result;
	}

}
