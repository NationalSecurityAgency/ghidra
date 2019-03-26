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
package ghidra.app.util.datatype.microsoft;

import ghidra.app.util.datatype.microsoft.GuidUtil.GuidType;

public class GuidInfo {
	
	protected final String guidString;
	protected final String guidName;
	protected final GuidType guidType;
	
	public GuidInfo(String guidString, String name, GuidType type) throws IllegalArgumentException {
		this.guidString = guidString;
		this.guidName = name;
		this.guidType = type;
	}

	public final String getGuidString() {
		return guidString;
	}

	public final String getName() {
		return guidName;
	}

	public final GuidType getType() {
		return guidType;
	}
	
	public String getUniqueIdString() {
		return guidString;
	}
}
