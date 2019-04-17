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
package ghidra.program.model.listing;

public class LabelString {
	
	public enum LabelType { CODE_LABEL, VARIABLE, EXTERNAL }

	public static final LabelType CODE_LABEL = LabelType.CODE_LABEL;
	public static final LabelType VARIABLE = LabelType.VARIABLE;
	public static final LabelType EXTERNAL = LabelType.EXTERNAL;
	
	private final String label;
	private final LabelType type;

	public LabelString(String label, LabelType type) {
		this.label = label;
		this.type = type;
	}

	@Override
	public String toString() {
		return label;
	}
	
	public LabelType getLabelType() {
		return type;
	}

}
