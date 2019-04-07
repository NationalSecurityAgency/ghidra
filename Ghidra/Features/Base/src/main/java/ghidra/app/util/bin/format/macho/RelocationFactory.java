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
package ghidra.app.util.bin.format.macho;

import ghidra.app.util.bin.format.*;

import java.io.*;

public final class RelocationFactory {

	public final static int  SECTION = 0xaaa;
	public final static int EXTERNAL = 0xbbb;
	public final static int    LOCAL = 0xccc;

	public final static RelocationInfo readRelocation(FactoryBundledWithBinaryReader reader, boolean is32bit) throws IOException {
		long relocIndex = reader.getPointerIndex();
		RelocationInfo info = RelocationInfo.createRelocationInfo(reader);
		if ((info.getAddress() & ScatteredRelocationInfo.R_SCATTERED) == 0) {
			return info;
		}
		reader.setPointerIndex(relocIndex);
		return ScatteredRelocationInfo.createScatteredRelocationInfo(reader);
	}

	public final static String getRelocationDescription(MachHeader header, RelocationInfo relocation) {
		switch (header.getCpuType()) {
			case CpuTypes.CPU_TYPE_POWERPC:
			case CpuTypes.CPU_TYPE_POWERPC64:
			{
				RelocationTypePPC [] values = RelocationTypePPC.values();
				for (RelocationTypePPC value : values) {
					if (value.ordinal() == relocation.getType()) {
						return value.name();
					}
				}
				break;
			}
			case CpuTypes.CPU_TYPE_X86:
			{
				RelocationTypeX86_32 [] values = RelocationTypeX86_32.values();
				for (RelocationTypeX86_32 value : values) {
					if (value.ordinal() == relocation.getType()) {
						return value.name();
					}
				}
				break;
			}
			case CpuTypes.CPU_TYPE_X86_64:
			{
				RelocationTypeX86_64 [] values = RelocationTypeX86_64.values();
				for (RelocationTypeX86_64 value : values) {
					if (value.ordinal() == relocation.getType()) {
						return value.name();
					}
				}
				break;
			}
			case CpuTypes.CPU_TYPE_ARM:
			{
				RelocationTypeARM [] values = RelocationTypeARM.values();
				for (RelocationTypeARM value : values) {
					if (value.ordinal() == relocation.getType()) {
						return value.name();
					}
				}
				break;
			}
			case CpuTypes.CPU_TYPE_ARM_64:
			{
				RelocationTypeARM64 [] values = RelocationTypeARM64.values();
				for (RelocationTypeARM64 value : values) {
					if (value.ordinal() == relocation.getType()) {
						return value.name();
					}
				}
				break;
			}
			default:
			{
				RelocationTypeGeneric [] values = RelocationTypeGeneric.values();
				for (RelocationTypeGeneric value : values) {
					if (value.ordinal() == relocation.getType()) {
						return value.name();
					}
				}
				break;
			}
		}
		return "Unknown Relocation Type: 0x"+Integer.toHexString(relocation.getType());
	}
}
