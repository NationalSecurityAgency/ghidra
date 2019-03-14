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

import java.util.*;

import org.apache.commons.collections4.map.HashedMap;

import ghidra.xml.XmlParseException;


/**
 *  A node in a decision tree.  Each node contains exactly one constraint and a map of property
 *  values.
 *
 * @param <T> the type of objects that the constraint operates on.
 */
public class DecisionNode<T> {
	private Map<String, PropertyValue> propertyMap = new HashedMap<String, PropertyValue>();
	private Constraint<T> constraint;
	private List<DecisionNode<T>> children = new ArrayList<DecisionNode<T>>();
	private DecisionNode<T> parent;

	public DecisionNode(Constraint<T> constraint, DecisionNode<T> parent) {
		this.constraint = constraint;
		this.parent = parent;
	}

	public DecisionNode<T> getOrCreateNodeForContraint(Constraint<T> newConstraint) {
		for (DecisionNode<T> child : children) {
			if (newConstraint.equals(child.constraint)) {
				return child;
			}
		}
		DecisionNode<T> newChild = new DecisionNode<T>(newConstraint, this);
		children.add(newChild);
		return newChild;
	}

	public void setProperty(String propertyName, String value, String source)
			throws XmlParseException {
		if (propertyMap.containsKey(propertyName)) {
			throw new XmlParseException("Attempted to overwrite property value for " +
				propertyName + " in contraint node: " + this);
		}
		propertyMap.put(propertyName, new PropertyValue(value, source));
	}

	public boolean populateDecisions(T t, DecisionSet decisionSet, String propertyName) {
		if (!constraint.isSatisfied(t)) {
			return false;
		}

		boolean decisionFound = false;
		for (DecisionNode<T> child : children) {
			decisionFound |= child.populateDecisions(t, decisionSet, propertyName);
		}

		// if no child found a more specific decision, see if we have a value for the property
		if (!decisionFound && propertyMap.containsKey(propertyName)) {
			PropertyValue value = propertyMap.get(propertyName);
			List<String> decisionPath = getDecisionPath();
			decisionSet.addDecision(new Decision(value.value, decisionPath, value.source));
			decisionFound = true;
		}

		return decisionFound;
	}

	protected List<String> getDecisionPath() {
		List<String> decisionPath = parent.getDecisionPath();
		decisionPath.add(constraint.getDescription());
		return decisionPath;
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		List<String> decisionPath = getDecisionPath();
		for (String string : decisionPath) {
			buf.append("/");
			buf.append(string);
		}
		return buf.toString();
	}

	static class PropertyValue {
		String value;
		String source;

		PropertyValue(String value, String source) {
			this.value = value;
			this.source = source;
		}
	}
}
