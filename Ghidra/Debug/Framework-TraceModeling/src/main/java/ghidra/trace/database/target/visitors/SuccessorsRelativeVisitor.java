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
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter;

public class SuccessorsRelativeVisitor implements SpanIntersectingVisitor {

	protected final PathFilter filter;

	public SuccessorsRelativeVisitor(PathFilter filter) {
		this.filter = filter;
	}

	@Override
	public TraceObjectValPath composePath(TraceObjectValPath pre,
			TraceObjectValue value) {
		return pre == null ? TraceObjectValPath.of() : pre.append(value);
	}

	@Override
	public VisitResult visitValue(TraceObjectValue value, TraceObjectValPath valPath) {
		KeyPath path = valPath.getPath();
		return VisitResult.result(filter.matches(path),
			filter.successorCouldMatch(path, true) && value.isObject());
	}

	@Override
	public TraceObject continueObject(TraceObjectValue value) {
		return value.isObject() ? value.getChild() : null;
	}

	@Override
	public Stream<? extends TraceObjectValue> continueValues(TraceObject object,
			Lifespan span, TraceObjectValPath pre) {
		Set<String> nextKeys = filter.getNextKeys(pre.getPath());
		if (nextKeys.isEmpty()) {
			return Stream.empty();
		}

		Stream<? extends TraceObjectValue> attrStream;
		if (nextKeys.contains("")) {
			attrStream = object.getAttributes(span).stream();
		}
		else {
			attrStream = Stream.empty();
		}

		Stream<? extends TraceObjectValue> elemStream;
		if (nextKeys.contains("[]")) {
			elemStream = object.getElements(span).stream();
		}
		else {
			elemStream = Stream.empty();
		}

		Stream<TraceObjectValue> restStream = nextKeys.stream()
				.filter(k -> !"".equals(k) && !"[]".equals(k))
				.flatMap(k -> object.getValues(span, k).stream());

		return Stream.concat(Stream.concat(attrStream, elemStream), restStream);
	}
}
