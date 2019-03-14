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
package ghidra.app.util.bin.format.pef;

/**
 * Imported and exported symbol classes
 */
public enum SymbolClass {
	/** A code address */
	kPEFCodeSymbol(0x00),
	/** A data address */
	kPEFDataSymbol(0x01),
	/** A standard procedure pointer */
	kPEFTVectSymbol(0x02),
	/** A direct data area (table of contents) symbol */
	kPEFTOCSymbol(0x03),
	/** A linker-inserted glue symbol */
	kPEFGlueSymbol(0x04),
	/** A undefined symbol */
	kPEFUndefinedSymbol(0x0f);

	private int value;

	private SymbolClass(int value) {
		this.value = value;
	}

	public int value() {
		return value;
	}

	public static SymbolClass get(int value) {
		SymbolClass [] symbolClasses = values();
		for (SymbolClass symbolClass : symbolClasses) {
			if (symbolClass.value == value) {
				return symbolClass;
			}
		}
		return null;
	}	
}
