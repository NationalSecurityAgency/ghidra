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

import ghidra.dbg.util.PathPredicates;
import ghidra.trace.database.target.InternalTreeTraversal.SpanIntersectingVisitor;
import ghidra.trace.database.target.InternalTreeTraversal.VisitResult;

public class InternalAncestorsRelativeVisitor implements SpanIntersectingVisitor {

	protected final PathPredicates predicates;

	public InternalAncestorsRelativeVisitor(PathPredicates predicates) {
		this.predicates = predicates;
	}

	@Override
	public DBTraceObjectValPath composePath(DBTraceObjectValPath pre,
			InternalTraceObjectValue value) {
		return pre == null ? DBTraceObjectValPath.of() : pre.prepend(value);
	}

	@Override
	public VisitResult visitValue(InternalTraceObjectValue value, DBTraceObjectValPath path) {
		List<String> keyList = path.getKeyList();
		return VisitResult.result(predicates.matches(keyList),
			predicates.ancestorCouldMatchRight(keyList, true) && value.getChildOrNull() != null);
	}

	@Override
	public DBTraceObject continueObject(InternalTraceObjectValue value) {
		return value.getParent();
	}

	@Override
	public Stream<? extends InternalTraceObjectValue> continueValues(DBTraceObject object,
			Range<Long> span, DBTraceObjectValPath pre) {
		Set<String> prevKeys = predicates.getPrevKeys(pre.getKeyList());
		if (prevKeys.isEmpty()) {
			return Stream.empty();
		}

		return object.doGetParents()
				.stream()
				.filter(v -> PathPredicates.anyMatches(prevKeys, v.getEntryKey()));
	}
}
