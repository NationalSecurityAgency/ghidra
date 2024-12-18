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
public interface TargetArrayDataType extends TargetDataType {
	public class DefaultTargetArrayDataType implements TargetArrayDataType {
		protected final TargetDataType elementType;
		protected final int elementCount;

		public DefaultTargetArrayDataType(TargetDataType elementType, int elementCount) {
			this.elementType = elementType;
			this.elementCount = elementCount;
		}

		@Override
		public TargetDataType getElementType() {
			return elementType;
		}

		@Override
		public int getElementCount() {
			return elementCount;
		}

		@Override
		public JsonElement toJson() {
			JsonObject object = new JsonObject();
			object.add("elementType", elementType.toJson());
			object.addProperty("elementCount", elementCount);
			return object;
		}
	}

	TargetDataType getElementType();

	int getElementCount();
}
