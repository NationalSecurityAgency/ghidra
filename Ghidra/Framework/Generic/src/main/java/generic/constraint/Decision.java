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

import java.util.List;

/**
 * Result object from getting values that match the constraints for given test object.
 */
public class Decision {

	private String value;
	private List<String> decisionPath;
	private String source;

	public Decision(String value, List<String> decisionPath, String source) {
		this.value = value;
		this.decisionPath = decisionPath;
		this.source = source;

	}

	/**
	 * Returns the value of the property for which this decision matched the constraints
	 * @return  the value of the property for which this decision matched the constraints
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Returns the constraint source file that added the value for this decision.
	 * @return  the constraint source file that added the value for this decision.
	 */
	public String getSource() {
		return source;
	}

	/**
	 * Returns a list of strings where each string is a description of the constraint that passed
	 * to reach this decision.
	 * @return  a list of strings where each string is a description of the constraint that passed
	 * to reach this decision.
	 */
	public List<String> getDecisionPath() {
		return decisionPath;
	}

	/**
	 * Returns a string that is a description of the constraints that passed
	 * to reach this decision.
	 * @return a string that is a description of the constraints that passed
	 * to reach this decision.
	 */
	public String getDescisionPathString() {
		StringBuilder builder = new StringBuilder();
		for (String string : decisionPath) {
			builder.append(string);
			builder.append("\n");
		}
		return builder.toString();
	}

}
