/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.constraint;

import java.util.ArrayList;
import java.util.List;

/**
 * Special root node for a decision tree.  Root nodes don't have a real constraint, so 
 * a dummy constraint that is always satisfied is used.
 *
 * @param <T> the type of object used to test constraints.s
 */
public class RootDecisionNode<T> extends DecisionNode<T> {

	public RootDecisionNode() {
		super(new DummyConstraint<T>(), null);
	}

	@Override
	protected List<String> getDecisionPath() {
		return new ArrayList<String>();
	}

	private static class DummyConstraint<T> extends Constraint<T> {

		public DummyConstraint() {
			super("");
		}

		@Override
		public boolean isSatisfied(T t) {
			return true;
		}

		@Override
		public void loadConstraintData(ConstraintData data) {
			// nothing to load
		}

		@Override
		public boolean equals(Object obj) {
			return this == obj;
		}

		@Override
		public String getDescription() {
			return null;
		}

	}
}
