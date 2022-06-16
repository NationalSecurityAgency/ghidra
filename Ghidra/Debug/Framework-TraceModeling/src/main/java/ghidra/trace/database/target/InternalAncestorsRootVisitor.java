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

import java.util.stream.Stream;

import com.google.common.collect.Range;

import ghidra.dbg.util.PathPredicates;
import ghidra.trace.database.target.InternalTreeTraversal.SpanIntersectingVisitor;
import ghidra.trace.database.target.InternalTreeTraversal.VisitResult;

public class InternalAncestorsRootVisitor implements SpanIntersectingVisitor {

	protected final PathPredicates predicates;

	public InternalAncestorsRootVisitor(PathPredicates predicates) {
		this.predicates = predicates;
	}

	@Override
	public DBTraceObjectValPath composePath(DBTraceObjectValPath pre,
			InternalTraceObjectValue value) {
		return pre == null ? DBTraceObjectValPath.of() : pre.prepend(value);
	}

	@Override
	public VisitResult visitValue(InternalTraceObjectValue value, DBTraceObjectValPath path) {
		return VisitResult.result(
			predicates.matches(value.getParent().getCanonicalPath().getKeyList()), true);
	}

	@Override
	public DBTraceObject continueObject(InternalTraceObjectValue value) {
		return value.getParent();
	}

	@Override
	public Stream<? extends InternalTraceObjectValue> continueValues(DBTraceObject object,
			Range<Long> span, DBTraceObjectValPath path) {
		if (object.isRoot()) {
			return Stream.empty();
		}
		/**
		 * Can't really filter the parent values by predicates here, since the predicates are not
		 * matching relative paths, but canonical paths.
		 */
		return object.getParents().stream().filter(v -> !path.contains(v));
	}
}
