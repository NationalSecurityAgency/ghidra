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
package ghidra.app.util.bin.format.elf.relocation;

public enum eBPF_ElfRelocationType implements ElfRelocationType {

	R_BPF_NONE(0),			// No operation needed
	R_BPF_64_64(1),			// S + A
	R_BPF_64_ABS64(2),		// S + A
	R_BPF_64_ABS32(3),		// S + A
	R_BPF_64_NODYLD32(4),	// S + A

	R_BPF_64_32(10),		// (S + A) / 8 - 1

	R_BPF_GNU_64_16(256);

	public final int typeId;

	private eBPF_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
