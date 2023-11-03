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
package ghidra.util.database.spatial.hyper;

public interface ULongDimension<P extends HyperPoint, B extends HyperBox<P, B>>
		extends Dimension<Long, P, B> {

	@Override
	default int compare(Long a, Long b) {
		return Long.compareUnsigned(a, b);
	}

	@Override
	default double distance(Long a, Long b) {
		return a - b;
	}

	@Override
	default Long mid(Long a, Long b) {
		return a + Long.divideUnsigned(b - a, 2);
	}

	@Override
	default Long absoluteMin() {
		return 0L;
	}

	@Override
	default Long absoluteMax() {
		return -1L;
	}
}
