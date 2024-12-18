/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.dbg.attributes;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

@Deprecated(forRemoval = true, since = "11.2")
public interface TargetPointerDataType extends TargetDataType {
	public class DefaultTargetPointerDataType implements TargetPointerDataType {
		protected final TargetDataType referentType;

		public DefaultTargetPointerDataType(TargetDataType referentType) {
			this.referentType = referentType;
		}

		@Override
		public TargetDataType getReferentType() {
			return referentType;
		}

		@Override
		public JsonElement toJson() {
			JsonObject object = new JsonObject();
			object.add("referentType", referentType.toJson());
			return object;
		}
	}

	TargetDataType getReferentType();
}
