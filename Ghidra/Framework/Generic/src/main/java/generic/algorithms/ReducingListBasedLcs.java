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
package generic.algorithms;

import java.util.List;

/**
 * An implementation of the {@link ReducingLcs} that takes as its input a list of {@literal <T>}items, where
 * the list is the 'sequence' being checked for the Longest Common Subsequence.
 *
 * @param <T> the type of the item in the sequence of items
 */
public class ReducingListBasedLcs<T> extends ReducingLcs<List<T>, T> {

	public ReducingListBasedLcs(List<T> x, List<T> y) {
		super(x, y);
	}

	@Override
	protected boolean matches(T x, T y) {
		return x.equals(y);
	}

	@Override
	protected List<T> reduce(List<T> i, int start, int end) {
		return i.subList(start, end);
	}

	@Override
	protected int lengthOf(List<T> i) {
		return i.size();
	}

	@Override
	protected T valueOf(List<T> i, int offset) {
		return i.get(offset);
	}
}
