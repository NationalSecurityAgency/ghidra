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
package ghidra.app.plugin.core.script;

public class IngredientDescription {
	private boolean visited;
	private String id;
	private String label;
	private int type;
	private Object defaultValue;

	public IngredientDescription(String id, String label, int type, Object defaultValue) {
		this.id = id;
		this.label = label;
		this.type = type;
		this.defaultValue = defaultValue;
		visited = false;
	}

	public boolean wasVisited() {
		return visited;
	}

	public String getLabel() {
		return label;
	}

	public String getID() {
		return id;
	}

	public int getType() {
		return type;
	}

	public Object getDefaultValue() {
		return defaultValue;
	}

}
