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
 * The result object returned from a scan of a decision tree looking for property values that
 * match the constrains for some test object.
 */
public class DecisionSet {

	private List<Decision> decisionList = new ArrayList<Decision>();
	private String propertyName;

	public DecisionSet(String propertyName) {
		this.propertyName = propertyName;
	}

	/**
	 * Returns a list of all the decisions whose descision path constraints matched the given
	 * test object.
	 * @return  a list of all the decisions whose descision path constraints matched the given
	 * test object.
	 */
	public List<Decision> getDecisions() {
		return decisionList;
	}

	/**
	 * Returns a list of property values from decision paths that matched the constraints.
	 * @return  a list of property values from decision paths that matched the constraints.
	 */
	public List<String> getValues() {
		List<String> values = new ArrayList<String>(decisionList.size());
		for (Decision decision : decisionList) {
			values.add(decision.getValue());
		}
		return values;
	}

	/**
	 * Returns the name of the property that was scanned for in the decision tree.
	 * @return  the name of the property that was scanned for in the decision tree.
	 */
	public String getDecisionPropertyName() {
		return propertyName;
	}

	void addDecision(Decision decision) {
		decisionList.add(decision);
	}

	/** 
	 * Returns true if this decisionSet has no results.
	 * @return  true if this decisionSet has no results.
	 */
	public boolean isEmpty() {
		return decisionList.isEmpty();
	}
}
