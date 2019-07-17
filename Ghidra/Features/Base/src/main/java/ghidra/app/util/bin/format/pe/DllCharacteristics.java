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
package ghidra.app.util.bin.format.pe;

import java.util.HashSet;
import java.util.Set;

public enum DllCharacteristics {

	IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 0x0020, "Image can handle a high entropy 64-bit virtual address space."),
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", 0x0040, "DLL can be relocated at load time."),
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", 0x0080, "Code Integrity checks are enforced."),
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT("IMAGE_DLLCHARACTERISTICS_NX_COMPAT", 0x0100, "Image is NX compatible."),
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", 0x0200, "Isolation aware, but do not isolate the image."),
	IMAGE_DLLCHARACTERISTICS_NO_SEH("IMAGE_DLLCHARACTERISTICS_NO_SEH", 0x0400, "Does not use structured exception (SE) handling. No SE handler may be called in this image."),
	IMAGE_DLLCHARACTERISTICS_NO_BIND("IMAGE_DLLCHARACTERISTICS_NO_BIND", 0x0800, "Do not bind the image."),
	IMAGE_DLLCHARACTERISTICS_APPCONTAINER("IMAGE_DLLCHARACTERISTICS_APPCONTAINER", 0x1000, "Image must execute in an AppContainer."),
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", 0x2000, "A WDM driver."),
	IMAGE_DLLCHARACTERISTICS_GUARD_CF("IMAGE_DLLCHARACTERISTICS_GUARD_CF", 0x4000, "Image supports Control Flow Guard."),
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", 0x8000, "Terminal Server aware.");

	private final String alias;
	private final int mask;
	private final String description;

	private DllCharacteristics(String alias, int mask, String description) {
		this.alias = alias;
		this.mask = mask;
		this.description = description;
	}

	public String getAlias() {
		return alias;
	}

	public int getMask() {
		return mask;
	}

	public String getDescription() {
		return description;
	}

	public static Set<DllCharacteristics> resolveCharacteristics(int value) {
		Set<DllCharacteristics> applied = new HashSet<>();
		for (DllCharacteristics ch : values()) {
			if ((ch.getMask() & value) == ch.getMask()) {
				applied.add(ch);
			}
		}
		return applied;
	}

}
