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

import java.util.*;
import java.util.stream.Stream;

import ghidra.dbg.util.PathPredicates;
import ghidra.trace.database.target.visitors.TreeTraversal.VisitResult;
import ghidra.trace.database.target.visitors.TreeTraversal.Visitor;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;

public class CanonicalSuccessorsRelativeVisitor implements Visitor {

	protected final PathPredicates predicates;
	protected final Set<TraceObject> seen = new HashSet<>();

	public CanonicalSuccessorsRelativeVisitor(PathPredicates predicates) {
		this.predicates = predicates;
	}

	@Override
	public Lifespan composeSpan(Lifespan pre, TraceObjectValue value) {
		return Lifespan.ALL;
	}

	@Override
	public TraceObjectValPath composePath(TraceObjectValPath pre,
			TraceObjectValue value) {
		return pre == null ? TraceObjectValPath.of() : pre.append(value);
	}

	@Override
	public VisitResult visitValue(TraceObjectValue value, TraceObjectValPath path) {
		List<String> keyList = path.getKeyList();
		return VisitResult.result(predicates.matches(keyList),
			predicates.successorCouldMatch(keyList, true) && value.isObject());
	}

	@Override
	public TraceObject continueObject(TraceObjectValue value) {
		return value.isObject() ? value.getChild() : null;
	}

	protected TraceObjectValue getCanonicalValue(TraceObject parent, String key) {
		return parent.getOrderedValues(Lifespan.ALL, key, true)
				.filter(TraceObjectValue::isCanonical)
				.findFirst()
				.orElse(null);
	}

	@Override
	public Stream<? extends TraceObjectValue> continueValues(TraceObject object,
			Lifespan span, TraceObjectValPath pre) {
		Set<String> nextKeys = predicates.getNextKeys(pre.getKeyList());
		if (nextKeys.isEmpty()) {
			return Stream.empty();
		}

		Stream<? extends TraceObjectValue> attrStream;
		if (nextKeys.contains("")) {
			attrStream = object.getAttributes().stream().filter(TraceObjectValue::isCanonical);
		}
		else {
			attrStream = Stream.empty();
		}

		Stream<? extends TraceObjectValue> elemStream;
		if (nextKeys.contains("[]")) {
			elemStream = object.getElements().stream().filter(TraceObjectValue::isCanonical);
		}
		else {
			elemStream = Stream.empty();
		}

		Stream<TraceObjectValue> restStream = nextKeys.stream()
				.filter(k -> !"".equals(k) && !"[]".equals(k))
				.map(k -> getCanonicalValue(object, k));

		return Stream.concat(Stream.concat(attrStream, elemStream), restStream);
	}
}
