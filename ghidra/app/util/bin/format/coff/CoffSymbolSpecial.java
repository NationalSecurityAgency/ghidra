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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public final class CoffSymbolSpecial {

	/** file name */
	public final static String DOT_FILE    = ".file";
	/** address of the .text section */
	public final static String DOT_TEXT    = ".text";
	/** address of the .data section */
	public final static String DOT_DATA    = ".data";
	/** address of the .bss section */
	public final static String DOT_BSS     = ".bss";
	/** address of the beginning of a block */
	public final static String DOT_BB      = ".bb";
	/** address of the end of a block */
	public final static String DOT_EB      = ".eb";
	/** address of the beginning of a function */
	public final static String DOT_BF      = ".bf";
	/** address of the end of a function */
	public final static String DOT_EF      = ".ef";
	/** Pointer to a structure or union that is returned by a function. */
	public final static String DOT_TARGET  = ".target";
	/** Dummy tag name for a structure, union, or enumeration. */
	public final static String DOT_NFAKE   = ".nfake";
	/** End of a structure, union, or enumeration. */
	public final static String DOT_EOS     = ".eos";
	/** Next available address after the end of the .text output section. */
	public final static String DOT_ETEXT   = "etext";
	/** Next available address after the end of the .data output section. */
	public final static String DOT_EDATA   = "edata";
	/** Next available address after the end of the .bss output section. */
	public final static String DOT_END     = "end";

	public final static boolean isSpecial(CoffSymbol symbol) {
		Field[] declaredFields = CoffMachineType.class.getDeclaredFields();
		for (Field field : declaredFields) {
			int modifiers = field.getModifiers();
			if (!Modifier.isFinal(modifiers)) {
				continue;
			}
			if (!Modifier.isStatic(modifiers)) {
				continue;
			}
			if (!field.getName().startsWith("DOT_")) {
				continue;
			}
			try {
				String value = (String)field.get(null);
				if (value != null && value.equals(symbol.getName())) {
					return true;
				}
			}
			catch (IllegalAccessException e) {}
		}
		return false;
	}

	public int getStorageClass(CoffSymbol specialSymbol) {
		if (specialSymbol.getName().equals(DOT_FILE)) {
			return CoffSymbolStorageClass.C_FILE;
		}
		else if (specialSymbol.getName().equals(DOT_BB)) {
			return CoffSymbolStorageClass.C_BLOCK;
		}
		else if (specialSymbol.getName().equals(DOT_EB)) {
			return CoffSymbolStorageClass.C_BLOCK;
		}
		else if (specialSymbol.getName().equals(DOT_BF)) {
			return CoffSymbolStorageClass.C_FCN;
		}
		else if (specialSymbol.getName().equals(DOT_EF)) {
			return CoffSymbolStorageClass.C_FCN;
		}
		else if (specialSymbol.getName().equals(DOT_EOS)) {
			return CoffSymbolStorageClass.C_EOS;
		}
		else if (specialSymbol.getName().equals(DOT_TEXT)) {
			return CoffSymbolStorageClass.C_STAT;
		}
		else if (specialSymbol.getName().equals(DOT_DATA)) {
			return CoffSymbolStorageClass.C_STAT;
		}
		else if (specialSymbol.getName().equals(DOT_BSS)) {
			return CoffSymbolStorageClass.C_STAT;
		}
		return -1;
	}
}
