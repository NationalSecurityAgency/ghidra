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

import java.util.stream.Stream;

import ghidra.trace.database.target.visitors.TreeTraversal.SpanIntersectingVisitor;
import ghidra.trace.database.target.visitors.TreeTraversal.VisitResult;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.path.PathFilter;

public class AncestorsRootVisitor implements SpanIntersectingVisitor {

	protected final PathFilter filter;

	public AncestorsRootVisitor(PathFilter filter) {
		this.filter = filter;
	}

	@Override
	public TraceObjectValPath composePath(TraceObjectValPath pre,
			TraceObjectValue value) {
		return pre == null ? TraceObjectValPath.of() : pre.prepend(value);
	}

	@Override
	public VisitResult visitValue(TraceObjectValue value, TraceObjectValPath path) {
		return VisitResult.result(filter.matches(value.getParent().getCanonicalPath()), true);
	}

	@Override
	public TraceObject continueObject(TraceObjectValue value) {
		return value.getParent();
	}

	@Override
	public Stream<? extends TraceObjectValue> continueValues(TraceObject object,
			Lifespan span, TraceObjectValPath path) {
		if (object.isRoot()) {
			return Stream.empty();
		}
		/**
		 * Can't really use filter for parent values here. The filter does not match relative paths,
		 * but canonical paths.
		 */
		return object.getParents(span).stream().filter(v -> !path.contains(v));
	}
}
