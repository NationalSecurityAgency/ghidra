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
package ghidra.util;

import java.util.Comparator;
import java.util.Iterator;
import java.util.function.BiPredicate;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

public abstract class PairingIteratorMerger<T, L extends T, R extends T>
		implements Iterator<Pair<L, R>>, Comparator<T>, BiPredicate<L, R> {
	private final Iterator<L> left;
	private final Iterator<R> right;

	private L nextL;
	private R nextR;

	public PairingIteratorMerger(Iterator<L> left, Iterator<R> right) {
		this.left = left;
		this.right = right;
		findNext();
	}

	protected void findNext() {
		while (true) {
			if (nextL == null) {
				if (!left.hasNext()) {
					return;
				}
				nextL = left.next();
			}
			if (nextR == null) {
				if (!right.hasNext()) {
					return;
				}
				nextR = right.next();
			}
			if (test(nextL, nextR)) {
				return;
			}
			int cmp = compare(nextL, nextR);
			if (cmp <= 0) {
				nextL = null;
			}
			if (cmp >= 0) {
				nextR = null;
			}
		}
	}

	@Override
	public boolean hasNext() {
		return nextL != null && nextR != null;
	}

	@Override
	public Pair<L, R> next() {
		Pair<L, R> ret = new ImmutablePair<>(nextL, nextR);
		findNext();
		return ret;
	}
}
