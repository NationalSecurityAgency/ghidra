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

import ghidra.dbg.attributes.TargetPrimitiveDataType.DefaultTargetPrimitiveDataType;
import ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind;

@Deprecated(forRemoval = true, since = "11.2")
public interface TargetDataType {
	TargetDataType UNDEFINED1 =
		new DefaultTargetPrimitiveDataType(PrimitiveKind.UNDEFINED, 1);

	JsonElement toJson();
}
