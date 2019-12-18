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
package ghidra.app.util.bin.format.coff;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

final class CoffSymbolAuxFactory {

	static CoffSymbolAux read(BinaryReader reader, CoffSymbol symbol) throws IOException {

		if (symbol.getDerivedType(1) == CoffSymbolType.DT_NON && symbol.getBasicType() == CoffSymbolType.T_NULL) {

			if (symbol.getStorageClass() == CoffSymbolStorageClass.C_FILE) {
				return new CoffSymbolAuxFilename(reader);
			}
			if (symbol.getStorageClass() == CoffSymbolStorageClass.C_STAT) {
				return new CoffSymbolAuxSection(reader);
			}
			if (symbol.getStorageClass() == CoffSymbolStorageClass.C_STRTAG ||
				symbol.getStorageClass() == CoffSymbolStorageClass.C_UNTAG ||
				symbol.getStorageClass() == CoffSymbolStorageClass.C_ENTAG) {
				return new CoffSymbolAuxTagName(reader);
			}
			if (symbol.getStorageClass() == CoffSymbolStorageClass.C_EOS) {
				return new CoffSymbolAuxEndOfStruct(reader);
			}
			if (symbol.getStorageClass() == CoffSymbolStorageClass.C_BLOCK) {
				return new CoffSymbolAuxBeginningOfBlock(reader);
			}
			if (symbol.getStorageClass() == CoffSymbolStorageClass.C_FCN) {
				return new CoffSymbolAuxFunction(reader);
			}
		}

		if (symbol.getDerivedType(1) == CoffSymbolType.DT_FCN) {
			if (symbol.getStorageClass() == CoffSymbolStorageClass.C_EXT) {
				return new CoffSymbolAuxFunction(reader);
			}
			if (symbol.getStorageClass() == CoffSymbolStorageClass.C_STAT) {
				return new CoffSymbolAuxFunction(reader);
			}
		}

		if (symbol.getDerivedType(1) == CoffSymbolType.DT_ARY) {
			switch (symbol.getStorageClass()) {
				case CoffSymbolStorageClass.C_AUTO:
				case CoffSymbolStorageClass.C_STAT:
				case CoffSymbolStorageClass.C_MOS:
				case CoffSymbolStorageClass.C_MOU:
				case CoffSymbolStorageClass.C_TPDEF:
					return new CoffSymbolAuxArray(reader);
			}
		}

		return new CoffSymbolAuxDefault(reader);
	}
	
}
