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
package generic.constraint;

/**
 * Constraints are used to make decisions to traverse a decision tree where each node in the
 * tree has a constraint that is used to decide if that node is part of the successful decision path. 
 *
 * @param <T>  The type of object that decisions will be made.
 */
public abstract class Constraint<T> {

	private String name;

	/**
	 * Constructor takes the name of the constraint.  This name will be tag used in the XML
	 * specification file.
	 * @param name the name of the constraint
	 */
	public Constraint(String name) {
		this.name = name;
	}

	/**
	 * Returns the name of the constraint.  Note: this name is also the XML tag used in the 
	 * constraints specification files.
	 * @return the name of the constraint
	 */
	public final String getName() {
		return name;
	}

	/**
	 * Returns true if the given object satisfies this constraint.
	 * @param t the object to test this constraint on.
	 * @return true if the given object satisfies this constraint.
	 */
	public abstract boolean isSatisfied(T t);

	/**
	 * Initialized this constraint state.  Attributes in the xml element with this constaints
	 * tag name will be extracted into the ConstraintData object for easy retrieval.
	 * @param data the ConstraintData object used to initialize this constraint.
	 */
	public abstract void loadConstraintData(ConstraintData data);

	@Override
	// overridden because it is critical that constraint object override equals.
	public abstract boolean equals(Object obj);

	/**
	 * Returns a description of this constraint (with its configuration data) to be used
	 * to journal the decision path that was taken.
	 * @return a description of this constraint with its configuration data.
	 */
	public abstract String getDescription();

}
