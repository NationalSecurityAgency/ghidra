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
package ghidra.trace.database.target;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import com.google.common.collect.Range;

import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathPredicates;
import ghidra.trace.database.target.InternalTreeTraversal.SpanIntersectingVisitor;
import ghidra.trace.database.target.InternalTreeTraversal.VisitResult;
import ghidra.trace.model.target.TraceObjectKeyPath;

public class InternalOrderedSuccessorsVisitor implements SpanIntersectingVisitor {

	protected final PathPredicates predicates;
	protected final boolean forward;

	public InternalOrderedSuccessorsVisitor(TraceObjectKeyPath path, boolean forward) {
		this.predicates = new PathPattern(path.getKeyList());
		this.forward = forward;
	}

	@Override
	public DBTraceObjectValPath composePath(DBTraceObjectValPath pre,
			InternalTraceObjectValue value) {
		return pre == null ? DBTraceObjectValPath.of() : pre.append(value);
	}

	@Override
	public VisitResult visitValue(InternalTraceObjectValue value, DBTraceObjectValPath path) {
		List<String> keyList = path.getKeyList();
		if (predicates.matches(keyList)) {
			// Singleton path, so if I match, no successor can
			return VisitResult.INCLUDE_FINISH;
		}
		if (value.getChildOrNull() == null || !predicates.successorCouldMatch(keyList, true)) {
			return VisitResult.EXCLUDE_FINISH;
		}
		return VisitResult.EXCLUDE_CONTINUE;
	}

	@Override
	public DBTraceObject continueObject(InternalTraceObjectValue value) {
		return value.getChildOrNull();
	}

	@Override
	public Stream<? extends InternalTraceObjectValue> continueValues(DBTraceObject object,
			Range<Long> span, DBTraceObjectValPath path) {
		Set<String> nextKeys = predicates.getNextKeys(path.getKeyList());
		if (nextKeys.isEmpty()) {
			return Stream.empty();
		}
		if (nextKeys.size() != 1) {
			throw new IllegalArgumentException("predicates must be a singleton");
		}
		String next = nextKeys.iterator().next();
		if (PathPattern.isWildcard(next)) {
			throw new IllegalArgumentException("predicates must be a singleton");
		}
		return object.doGetOrderedValues(span, next, forward);
	}
}
