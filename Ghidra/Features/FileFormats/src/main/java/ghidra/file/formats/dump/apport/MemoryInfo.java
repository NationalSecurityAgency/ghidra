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
package ghidra.file.formats.dump.apport;

public class MemoryInfo {

	public final static String NAME = "MINIDUMP_MEMORY_INFO";

	private long baseAddress;
	private long regionSize;
	private String permissions;
	private long rva;
	private String description;

	private String text;


	MemoryInfo(String text) {
		this.text = text;
		parse();
	}

	private void parse() {
		String[] split = text.trim().split("\\s+");
		String range = split[0];
		String[] rangeSplit = range.split("-");
		long start = Long.parseUnsignedLong(rangeSplit[0], 16);
		long stop = Long.parseUnsignedLong(rangeSplit[1], 16);
		baseAddress = start;
		regionSize = stop - start;
		setPermissions(split[1]);
		long offset = Long.parseUnsignedLong(split[2], 16);
		setRva(offset);
		if (split.length > 5) {
			setDescription(split[5]);
		}
	}


	public long getBaseAddress() {
		return baseAddress;
	}

	public void setBaseAddress(long baseAddress) {
		this.baseAddress = baseAddress;
	}

	public long getRegionSize() {
		return regionSize;
	}

	public void setRegionSize(long regionSize) {
		this.regionSize = regionSize;
	}

	public String getPermissions() {
		return permissions;
	}

	public void setPermissions(String permissions) {
		this.permissions = permissions;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public long getRva() {
		return rva;
	}

	public void setRva(long rva) {
		this.rva = rva;
	}
}
