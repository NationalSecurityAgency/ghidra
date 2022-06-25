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

public enum InternalTreeTraversal {
	INSTANCE;

	public enum VisitResult {
		INCLUDE_CONTINUE,
		INCLUDE_FINISH,
		EXCLUDE_CONTINUE,
		EXCLUDE_FINISH,
		;

		public static VisitResult result(boolean include, boolean cont) {
			if (include) {
				if (cont) {
					return INCLUDE_CONTINUE;
				}
				else {
					return INCLUDE_FINISH;
				}
			}
			else {
				if (cont) {
					return EXCLUDE_CONTINUE;
				}
				else {
					return EXCLUDE_FINISH;
				}
			}
		}
	}

	public interface Visitor {
		Range<Long> composeSpan(Range<Long> pre, InternalTraceObjectValue value);

		DBTraceObjectValPath composePath(DBTraceObjectValPath pre, InternalTraceObjectValue value);

		VisitResult visitValue(InternalTraceObjectValue value, DBTraceObjectValPath path);

		DBTraceObject continueObject(InternalTraceObjectValue value);

		Stream<? extends InternalTraceObjectValue> continueValues(DBTraceObject object,
				Range<Long> span, DBTraceObjectValPath path);
	}

	public interface SpanIntersectingVisitor extends Visitor {
		@Override
		default Range<Long> composeSpan(Range<Long> pre, InternalTraceObjectValue value) {
			Range<Long> valSpan = value.getLifespan();
			if (!pre.isConnected(valSpan)) {
				return null;
			}
			Range<Long> span = pre.intersection(valSpan);
			if (span.isEmpty()) {
				return null;
			}
			return span;
		}
	}

	public Stream<? extends DBTraceObjectValPath> walkValue(Visitor visitor,
			InternalTraceObjectValue value, Range<Long> span, DBTraceObjectValPath path) {
		Range<Long> compSpan = visitor.composeSpan(span, value);
		if (compSpan == null) {
			return Stream.empty();
		}
		DBTraceObjectValPath compPath = visitor.composePath(path, value);
		if (compPath == null) {
			return Stream.empty();
		}

		switch (visitor.visitValue(value, compPath)) {
			case INCLUDE_FINISH:
				return Stream.of(compPath);
			case EXCLUDE_FINISH:
				return Stream.empty();
			case INCLUDE_CONTINUE: {
				DBTraceObject object = visitor.continueObject(value);
				return Stream.concat(Stream.of(compPath),
					walkObject(visitor, object, compSpan, compPath));
			}
			case EXCLUDE_CONTINUE: {
				DBTraceObject object = visitor.continueObject(value);
				return walkObject(visitor, object, compSpan, compPath);
			}
		}
		throw new AssertionError();
	}

	public Stream<? extends DBTraceObjectValPath> walkObject(Visitor visitor, DBTraceObject object,
			Range<Long> span, DBTraceObjectValPath path) {
		return visitor.continueValues(object, span, path)
				.flatMap(v -> walkValue(visitor, v, span, path));
	}
}
