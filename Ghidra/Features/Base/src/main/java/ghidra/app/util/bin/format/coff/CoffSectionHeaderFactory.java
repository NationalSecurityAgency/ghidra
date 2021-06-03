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
package ghidra.app.util.bin.format.coff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

final class CoffSectionHeaderFactory {

	static CoffSectionHeader createSectionHeader(BinaryReader reader, CoffFileHeader header) throws IOException {
		switch (header.getMagic()) {
			case CoffMachineType.TICOFF1MAGIC:
				return new CoffSectionHeader1(reader, header);
			case CoffMachineType.TICOFF2MAGIC:
				return new CoffSectionHeader2(reader, header);
			case CoffMachineType.IMAGE_FILE_MACHINE_I960ROMAGIC:
			case CoffMachineType.IMAGE_FILE_MACHINE_I960RWMAGIC:
				return new CoffSectionHeader3(reader, header);
			default:
				return new CoffSectionHeader(reader, header);
		}
	}
}
