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
package ghidra.trace.database.target.visitors;

import java.util.Set;
import java.util.stream.Stream;

import ghidra.trace.database.target.visitors.TreeTraversal.SpanIntersectingVisitor;
import ghidra.trace.database.target.visitors.TreeTraversal.VisitResult;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.*;

public class OrderedSuccessorsVisitor implements SpanIntersectingVisitor {

	protected final PathFilter filter;
	protected final boolean forward;

	public OrderedSuccessorsVisitor(KeyPath path, boolean forward) {
		this.filter = new PathPattern(path);
		this.forward = forward;
	}

	@Override
	public TraceObjectValPath composePath(TraceObjectValPath pre,
			TraceObjectValue value) {
		return pre == null ? TraceObjectValPath.of() : pre.append(value);
	}

	@Override
	public VisitResult visitValue(TraceObjectValue value, TraceObjectValPath valPath) {
		KeyPath path = valPath.getPath();
		if (filter.matches(path)) {
			// Singleton path, so if I match, no successor can
			return VisitResult.INCLUDE_PRUNE;
		}
		if (!value.isObject() || !filter.successorCouldMatch(path, true)) {
			return VisitResult.EXCLUDE_PRUNE;
		}
		return VisitResult.EXCLUDE_DESCEND;
	}

	@Override
	public TraceObject continueObject(TraceObjectValue value) {
		return value.isObject() ? value.getChild() : null;
	}

	@Override
	public Stream<? extends TraceObjectValue> continueValues(TraceObject object,
			Lifespan span, TraceObjectValPath valPath) {
		Set<String> nextKeys = filter.getNextKeys(valPath.getPath());
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
		return object.getOrderedValues(span, next, forward);
	}
}
