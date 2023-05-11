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

import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;

/**
 * Support for traversing a trace's object tree
 * 
 * <p>
 * Many of these are already built into the object and value interfaces. Direct use of this
 * traversal support is only needed when performing customized traversals. In most cases, it's
 * sufficient to use a built-in traversal and filter the resulting stream. Customized traversal is
 * only needed when it's beneficial to prune subtrees in a way that no built-in traversal provides.
 */
public enum TreeTraversal {
	/** The singleton instance */
	INSTANCE;

	/**
	 * A result directing the traversal how to proceed
	 */
	public enum VisitResult {
		/**
		 * Include the value that was just traversed, and descend
		 */
		INCLUDE_DESCEND,
		/**
		 * Include the value that was just traversed, but prune its subtree
		 */
		INCLUDE_PRUNE,
		/**
		 * Exclude the value that was just traversed, but descend
		 */
		EXCLUDE_DESCEND,
		/**
		 * Exclude the value that was just traversed, and prune its subtree
		 */
		EXCLUDE_PRUNE,
		;

		/**
		 * Get the result that indicates the given inclusion and continuation
		 * 
		 * @param include true to include the value just traversed, false to exclude
		 * @param cont true to continue traversal, false to terminate
		 * @return the result
		 */
		public static VisitResult result(boolean include, boolean cont) {
			if (include) {
				if (cont) {
					return INCLUDE_DESCEND;
				}
				else {
					return INCLUDE_PRUNE;
				}
			}
			else {
				if (cont) {
					return EXCLUDE_DESCEND;
				}
				else {
					return EXCLUDE_PRUNE;
				}
			}
		}
	}

	/**
	 * An object-tree visitor
	 * 
	 * <p>
	 * Traversal starts at a seed object or value (node or edge, respectively) and proceeds in
	 * alternating fashion from object to value to object and so on via
	 * {@link #continueObject(TraceObjectValue)} and
	 * {@link #continueValues(TraceObject, Lifespan, TraceObjectValPath)}. Filtering is performed on
	 * values via {@link #visitValue(TraceObjectValue, TraceObjectValPath)}. As traversal descends,
	 * paths and spans are composed to inform filtering and construct the final result stream. Note
	 * that some traversals start at a seed and "descend" along the ancestry.
	 */
	public interface Visitor {
		/**
		 * When descending in a value, what span to consider in the subtree
		 * 
		 * <p>
		 * Usually this is intersection. See {@link SpanIntersectingVisitor}
		 * 
		 * @param pre the span composed from values from seed to but excluding the current value
		 * @param value the current value
		 * @return the span composed from values from seed to and including the current value
		 */
		Lifespan composeSpan(Lifespan pre, TraceObjectValue value);

		/**
		 * When descending in a value, what path leads to the value
		 * 
		 * <p>
		 * This is usually {@link TraceObjectValPath#append(TraceObjectValue)} or
		 * {@link TraceObjectValPath#prepend(TraceObjectValue)}.
		 * 
		 * @param pre the path from seed to the but excluding the current value
		 * @param value the path from seed to the and including the current value
		 * @return the path from seed to and including the current value
		 */
		TraceObjectValPath composePath(TraceObjectValPath pre, TraceObjectValue value);

		/**
		 * Visit a value
		 * 
		 * <p>
		 * Note that the path is the composed path, so it will likely have the current value at its
		 * beginning or end.
		 * 
		 * @param value the current value
		 * @param path the path from seed to value
		 * @return directions for how traversal should proceed
		 */
		VisitResult visitValue(TraceObjectValue value, TraceObjectValPath path);

		/**
		 * When descending in a value, the object to consider next
		 * 
		 * <p>
		 * This is usually {@link TraceObjectValue#getChild()} or
		 * {@link TraceObjectValue#getParent()}.
		 * 
		 * @param value the current value
		 * @return the next object
		 */
		TraceObject continueObject(TraceObjectValue value);

		/**
		 * When descending in an object, the values to consider next
		 * 
		 * @param object the current object
		 * @param span the composed span of values from seed to the current object
		 * @param path the path from seed to the current object
		 * @return the next values
		 */
		Stream<? extends TraceObjectValue> continueValues(TraceObject object,
				Lifespan span, TraceObjectValPath path);
	}

	/**
	 * A visitor providing default {@link #composeSpan(Lifespan, TraceObjectValue)} that intersects
	 * the spans
	 */
	public interface SpanIntersectingVisitor extends Visitor {
		@Override
		default Lifespan composeSpan(Lifespan pre, TraceObjectValue value) {
			Lifespan span = pre.intersect(value.getLifespan());
			return span.isEmpty() ? null : span;
		}
	}

	/**
	 * Walk a value and possibly its subtree
	 * 
	 * @param visitor the visitor
	 * @param value the current value
	 * @param span the composed span from seed to but excluding the current value
	 * @param path the path from seed to but excluding the current value
	 * @return the result stream of the value and subtree walked
	 */
	public Stream<? extends TraceObjectValPath> walkValue(Visitor visitor,
			TraceObjectValue value, Lifespan span, TraceObjectValPath path) {
		Lifespan compSpan = visitor.composeSpan(span, value);
		if (compSpan == null) {
			return Stream.empty();
		}
		TraceObjectValPath compPath = visitor.composePath(path, value);
		if (compPath == null) {
			return Stream.empty();
		}

		switch (visitor.visitValue(value, compPath)) {
			case INCLUDE_PRUNE:
				return Stream.of(compPath);
			case EXCLUDE_PRUNE:
				return Stream.empty();
			case INCLUDE_DESCEND: {
				TraceObject object = visitor.continueObject(value);
				return Stream.concat(Stream.of(compPath),
					walkObject(visitor, object, compSpan, compPath));
			}
			case EXCLUDE_DESCEND: {
				TraceObject object = visitor.continueObject(value);
				return walkObject(visitor, object, compSpan, compPath);
			}
		}
		throw new AssertionError();
	}

	/**
	 * Walk an object and its subtree
	 * 
	 * @param visitor the visitor
	 * @param object the current object
	 * @param span the composed span from seed to current object
	 * @param path the path from seed to current object
	 * @return the result stream of the object and subtree walked
	 */
	public Stream<? extends TraceObjectValPath> walkObject(Visitor visitor, TraceObject object,
			Lifespan span, TraceObjectValPath path) {
		return visitor.continueValues(object, span, path)
				.flatMap(v -> walkValue(visitor, v, span, path));
	}
}
