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
package ghidra.program.model.lang;

import org.apache.commons.lang3.StringUtils;

public enum Endian {
	BIG("big", "BE"), LITTLE("little", "LE");

	private final String name;
	private final String shortName;

	private Endian(String name, String shortName) {
		this.name = name;
		this.shortName = shortName;
	}

	public static Endian toEndian(String endianess) {
		if (endianess != null) {
			if ((Endian.BIG.toString().equalsIgnoreCase(endianess)) ||
				(Endian.BIG.toShortString().equalsIgnoreCase(endianess))) {
				return Endian.BIG;
			}
			else if ((Endian.LITTLE.toString().equalsIgnoreCase(endianess)) ||
				(Endian.LITTLE.toShortString().equalsIgnoreCase(endianess))) {
				return Endian.LITTLE;
			}
			else {
				return null;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return name;
	}

	public String toShortString() {
		return shortName;
	}

	public boolean isBigEndian() {
		return this == BIG;
	}

	public String getDisplayName() {
		return StringUtils.capitalize(name);
	}

}
