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
package ghidra.program.model.data.ISF;

import com.google.gson.JsonObject;

import ghidra.program.model.data.Enum;

public class IsfEnum implements IsfObject {

	public Integer size;
	public String base;
	public JsonObject constants = new JsonObject();

	public IsfEnum(Enum enumm) {
		size = enumm.getLength();
		base = "int";
		String[] names = enumm.getNames();
		for (int j = 0; j < names.length; j++) {
			constants.addProperty(names[j], enumm.getValue(names[j]));
		}
	}

}
