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
package ghidra.app.plugin.core.debug.service.modules;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import ghidra.app.services.MapEntry;
import ghidra.app.services.MapProposal;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;

public abstract class AbstractMapProposal<T, P, E extends MapEntry<T, P>>
		implements MapProposal<T, P, E> {

	protected abstract static class Matcher<T, P> {
		protected final T fromObject;
		protected final P toObject;
		protected final AddressRange fromRange;
		protected final AddressRange toRange;
		protected final double score;

		protected Matcher(T fromObject, P toObject) {
			this.fromObject = fromObject;
			this.toObject = toObject;
			this.fromRange = fromObject == null ? null : getFromRange();
			this.toRange = toObject == null ? null : getToRange();
			this.score = fromObject == null || toObject == null ? 0 : computeScore();
		}

		protected abstract AddressRange getFromRange();

		protected abstract AddressRange getToRange();

		protected double computeScore() {
			return computeKeyMatchScore() + computeLengthScore();
		}

		protected int computeKeyMatchScore() {
			return 3;
		}

		protected long shiftRight1RoundUp(long val) {
			if ((val & 1) == 1) {
				return (val >>> 1) + 1;
			}
			return val >>> 1;
		}

		protected double computeLengthScore() {
			long fLen = fromRange.getLength();
			long tLen = toRange.getLength();
			for (int bitsmatched = 64; bitsmatched > 0; bitsmatched--) {
				if ((fLen == tLen)) {
					return bitsmatched / 6.4d;
				}
				fLen = shiftRight1RoundUp(fLen);
				tLen = shiftRight1RoundUp(tLen);
			}
			return 0;
		}
	}

	protected static abstract class MatcherMap<K, T, P, M extends Matcher<T, P>> {
		protected Map<K, Set<T>> fromsByJoin = new LinkedHashMap<>();
		protected Map<T, M> map = new LinkedHashMap<>();

		protected abstract M newMatcher(T fromObject, P toObject);

		protected abstract K getFromJoinKey(T fromObject);

		protected abstract K getToJoinKey(P toObject);

		protected void processFromObject(T fromObject) {
			fromsByJoin.computeIfAbsent(getFromJoinKey(fromObject), k -> new LinkedHashSet<>())
					.add(fromObject);
		}

		protected void processToObject(P toObject) {
			Set<T> froms = fromsByJoin.get(getToJoinKey(toObject));
			if (froms == null) {
				return;
			}
			for (T f : froms) {
				M bestM = map.get(f);
				M candM = newMatcher(f, toObject);
				if (bestM == null || candM.score > bestM.score) {
					map.put(f, candM);
				}
			}
		}

		protected double averageScore() {
			return map.values()
					.stream()
					.reduce(0d, (s, m) -> s + m.score, Double::sum) /
				map.size();
		}

		protected <E> Map<T, E> computeMap(Function<M, E> newEntry) {
			return map.values()
					.stream()
					.filter(m -> m.fromObject != null && m.toObject != null)
					.collect(Collectors.toMap(m -> m.fromObject, newEntry));
		}

		protected P getToObject(T fromObject) {
			M m = map.get(fromObject);
			return m == null ? null : m.toObject;
		}
	}

	protected final Trace trace;
	protected final Program program;

	public AbstractMapProposal(Trace trace, Program program) {
		this.trace = trace;
		this.program = program;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public Program getProgram() {
		return program;
	}
}
