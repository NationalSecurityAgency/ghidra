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

import com.google.common.collect.Range;

import ghidra.lifecycle.Experimental;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectValue;

@Experimental
public class LifespanCorrector {
	/**
	 * A visitor for lifespan correction
	 * 
	 * <p>
	 * Implementors must implement only the upward pair, or only the downward pair
	 */
	public interface Visitor {
		/**
		 * Visit an object on the upward side of traversal
		 * 
		 * @param object the object
		 */
		default void visitObjectUpward(TraceObject object) {
		}

		/**
		 * Visit an object on the downward side of traversal
		 * 
		 * @param object the object
		 */
		default void visitObjectDownward(TraceObject object) {
		}

		/**
		 * Visit a value on the upward side of traversal
		 * 
		 * @param value the value, guaranteed to have a child
		 */
		default void visitValueUpward(TraceObjectValue value) {
		}

		/**
		 * Visit a value on the downward side of traversal
		 * 
		 * @param value the value, guaranteed to have a child
		 */
		default void visitValueDownward(TraceObjectValue value) {
		}
	}

	public enum Direction {
		ANCESTORS {
			@Override
			public void visit(TraceObject seed, Visitor visitor) {
				visitObjectAncestors(seed, visitor, UP | DOWN);
			}

		},
		SUCCESSORS {
			@Override
			public void visit(TraceObject seed, Visitor visitor) {
				visitObjectSuccessors(seed, visitor, true);
			}
		},
		BOTH {
			@Override
			public void visit(TraceObject seed, Visitor visitor) {
				visitObjectAncestors(seed, visitor, DOWN);
				visitObjectSuccessors(seed, visitor, false);
				visitObjectAncestors(seed, visitor, UP);
			}
		};

		static final int UP = 1;
		static final int DOWN = 2;

		public abstract void visit(TraceObject seed, Visitor visitor);

		void visitObjectAncestors(TraceObject object, Visitor visitor, int mode) {
			if ((mode & UP) == UP) {
				visitor.visitObjectUpward(object);
			}
			if (!object.isRoot()) {
				for (TraceObjectValue value : object.getParents()) {
					// Yes, over time, there may be multiple canonical values
					if (value.isCanonical() && !value.isDeleted()) {
						visitValueAncestors(value, visitor, mode);
					}
				}
			}
			if ((mode & DOWN) == DOWN) {
				visitor.visitObjectDownward(object);
			}
		}

		void visitValueAncestors(TraceObjectValue value, Visitor visitor, int mode) {
			visitor.visitValueUpward(value);
			visitObjectAncestors(value.getParent(), visitor, mode);
			visitor.visitValueDownward(value);
		}

		void visitObjectSuccessors(TraceObject object, Visitor visitor, boolean includeCur) {
			if (includeCur) {
				visitor.visitObjectDownward(object);
			}
			for (TraceObjectValue value : object.getValues()) {
				if (value.isCanonical() && !value.isDeleted()) {
					visitValueSuccessors(value, visitor);
				}
			}
			if (includeCur) {
				visitor.visitObjectUpward(object);
			}
		}

		void visitValueSuccessors(TraceObjectValue value, Visitor visitor) {
			if (!(value.getValue() instanceof TraceObject)) {
				return;
			}
			visitor.visitValueDownward(value);
			visitObjectSuccessors(value.getChild(), visitor, true);
			visitor.visitValueUpward(value);
		}
	}

	// TODO: Consider non-canonical paths?

	public enum Operation {
		EXPAND {
			@Override
			Visitor getVisitor(ConflictResolution resolution) {
				return new Visitor() {
					@Override
					public void visitObjectUpward(TraceObject object) {
						Range<Long> span = object.getLifespan();
						for (TraceObjectValue value : object.getValues()) {
							span = span.span(value.getLifespan());
						}
						object.setLifespan(span);
					}

					@Override
					public void visitValueUpward(TraceObjectValue value) {
						Range<Long> newLife =
							value.getLifespan().span(value.getChild().getLifespan());
						value.setLifespan(newLife, resolution);
					}
				};
			}
		},
		SHRINK {
			@Override
			Visitor getVisitor(ConflictResolution resolution) {
				return new Visitor() {
					@Override
					public void visitObjectDownward(TraceObject object) {
						for (TraceObjectValue value : object.getValues()) {
							if (!DBTraceUtils.intersect(object.getLifespan(),
								value.getLifespan())) {
								value.delete();
								continue;
							}
							value.setLifespan(
								value.getLifespan().intersection(object.getLifespan()), resolution);
						}
					}

					@Override
					public void visitValueDownward(TraceObjectValue value) {
						/**
						 * It'd be an odd circumstance for two canonical entries to exist for the
						 * same parent and child. If that happens, this will cause the child to
						 * become detached, since those entries cannot intersect.
						 */
						if (!DBTraceUtils.intersect(value.getLifespan(),
							value.getChild().getLifespan())) {
							value.getChild().delete();
							return;
						}
						Range<Long> newLife =
							value.getLifespan().intersection(value.getChild().getLifespan());
						value.getChild().setLifespan(newLife);
					}
				};
			}
		};

		abstract Visitor getVisitor(ConflictResolution resolution);
	}

	private final Direction direction;
	private final Operation operation;
	private final ConflictResolution resolution;

	public LifespanCorrector(Direction direction, Operation operation,
			ConflictResolution resolution) {
		this.direction = direction;
		this.operation = operation;
		this.resolution = resolution;
	}

	public void correctLifespans(TraceObject seed) {
		direction.visit(seed, operation.getVisitor(resolution));
	}
}
