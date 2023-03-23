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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.HashMap;
import java.util.Map;

import ghidra.util.Msg;

/**
 * Enum storing the type value of C13 Section along with the class of the section implementation.
 * The value is what will be parsed prior to the rest of record that will be parsed according to
 * its type.  The class information is available to ensure proper casting to the type specified.
 * <p>
 * Note that we have created two additional enumerates: one for values that don't match in the
 * {@link #fromValue(int)} method and can typically be used default switch cases.  The other
 * is used to "select" ALL standard C13 Section types when used appropriately.  Of course, there
 * is a chance that the enumerate values we have chosen for these could cause an unforeseen
 * problem, but we tried to choose values that will not be problematic.
 * <p>
 * Note that lookups by value mask off an "ignore" bit, and since we are an enum, we cannot store
 * the fact of ignore or not unless we double the number of enumerates.
 * However, we have incorporated a utility method testing the "ignore" value on the parsed value
 * prior to doing the lookup of with the {@link #fromValue(int)} method.
 */
enum C13Type {
	UNKNOWN(0x80000000, UnknownC13Section.class), // We created; fix/eliminate if causes problems
	ALL(0x00000000, C13Section.class), // We created; fix if causes problems
	SYMBOLS(0xf1, C13Symbols.class),
	LINES(0xf2, C13Lines.class),
	STRING_TABLE(0xf3, C13StringTable.class),
	FILE_CHECKSUMS(0xf4, C13FileChecksums.class),
	FRAMEDATA(0xf5, C13FrameData.class),
	INLINEE_LINES(0xf6, C13InlineeLines.class),
	CROSS_SCOPE_IMPORTS(0xf7, C13CrossScopeImports.class),
	CROSS_SCOPE_EXPORTS(0xf8, C13CrossScopeExports.class),
	IL_LINES(0xf9, C13IlLines.class),
	FUNC_MDTOKEN_MAP(0xfa, C13FuncMdTokenMap.class),
	TYPE_MDTOKEN_MAP(0xfb, C13TypeMdTokenMap.class),
	MERGED_ASSEMBLY_INPUT(0xfc, C13MergedAssemblyInput.class),
	COFF_SYMBOL_RVA(0xfd, C13CoffSymbolRva.class);

	private static final int IGNORE_BIT = 0x80000000;
	private static final int IGNORE_BIT_MASK = ~IGNORE_BIT;

	private static final Map<Integer, C13Type> BY_VALUE = new HashMap<>();
	private static final Map<Class<? extends C13Section>, C13Type> BY_CLASS_VALUE = new HashMap<>();
	static {
		for (C13Type val : values()) {
			BY_VALUE.put(val.value, val);
			BY_CLASS_VALUE.put(val.classValue, val);
		}
	}

	private final int value;
	private final Class<? extends C13Section> classValue;

	/**
	 * Returns the C13Type corresponding to the parse value for the C13 Section type.
	 * @param val the parse value
	 * @return the C13Type
	 */
	public static C13Type fromValue(int val) {
		C13Type t = BY_VALUE.getOrDefault(maskIgnore(val), UNKNOWN);
		if (t == UNKNOWN) {
			Msg.debug(C13Type.class, String.format("C13Debug - Unknown section type %08x", val));
		}
		return t;
	}

	/**
	 * Returns the C13Type which has the (parse) value that is used to identify a section of the
	 * type specified by the {@code classVal} parameter
	 * @param classVal the implementation class we are need
	 * @return the C13Type for this type
	 */
	public static C13Type fromClassValue(Class<? extends C13Section> classVal) {
		C13Type t = BY_CLASS_VALUE.getOrDefault(classVal, UNKNOWN);
		if (t == UNKNOWN) {
			Msg.debug(C13Type.class,
				String.format("C13Debug - Unknown classValue %s", classVal.getSimpleName()));
		}
		return t;
	}

	public static boolean ignore(int val) {
		return ((val & IGNORE_BIT) != 0);
	}

	public static int maskIgnore(int val) {
		return val & IGNORE_BIT_MASK;
	}

	private C13Type(int value, Class<? extends C13Section> classValue) {
		this.value = value;
		this.classValue = classValue;
	}

	/**
	 * Returns the value of the enum
	 * @return the value
	 */
	public int getValue() {
		return value;
	}

	/**
	 * Returns the Class that is associated with the enum
	 * @return the Class
	 */
	public Class<? extends C13Section> getSectionClass() {
		return classValue;
	}

}
