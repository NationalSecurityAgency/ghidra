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
package sarif.export;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ISF.IsfObject;
import sarif.SarifUtils;

public class SarifObject implements IsfObject {

	public static boolean SARIF = true;

	protected JsonObject message;
	protected String kind;
	protected String level;
	protected String ruleId;
	protected JsonArray locations;
	protected JsonObject properties;

	protected JsonObject element;

	public SarifObject(String key, String ruleKey, JsonElement element) {
		if (SARIF) {
			message = new JsonObject();
			message.addProperty("text", key);
			kind = "informational";  // convention specifies lower-case
			level = "none";
			ruleId = ruleKey;
			properties = new JsonObject();
			properties.add("additionalProperties", element);
		} else {
			this.element = (JsonObject) element;
			this.element.addProperty("key", key);
			this.element.addProperty("rule", ruleKey);
		}
	}

	public SarifObject(String key, String ruleKey, JsonElement tree, Address min, Address max) {
		this(key, ruleKey, tree);
		if (min != null) {
			writeLocations(min, max);
		}
	}

	public SarifObject(String key, String ruleKey, JsonElement tree, AddressSetView body) {
		this(key, ruleKey, tree);
		if (body != null) {
			writeLocations(body);
		}
	}

	protected void writeLocations(Address min, Address max) {
		if (SARIF) {
			locations = SarifUtils.setLocations(min, max);
		} else {
			element.addProperty("startAddress", min.toString(true));
			element.addProperty("stopAddress", max.toString(true));
		}
	}

	protected void writeLocations(AddressSetView set) {
		if (SARIF) {
			locations = SarifUtils.setLocations(set);
		} else {
			element.addProperty("startAddress", set.getMinAddress().toString(true));
			element.addProperty("stopAddress", set.getMaxAddress().toString(true));
		}
	}
}
