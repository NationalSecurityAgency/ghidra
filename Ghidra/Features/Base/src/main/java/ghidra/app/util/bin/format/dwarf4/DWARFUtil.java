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
package ghidra.app.util.bin.format.dwarf4;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFAttributeValue;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Conv;

public class DWARFUtil {
	/**
	 * Converts a integer value to its corresponding symbolic name from the set of
	 * "public static final" member variables in a class.
	 * <p>
	 * This is a bit of a hack and probably originated from pre-java Enum days.
	 *
	 * @param clazz The {@link Class} to search for the matching static value.
	 * @param value the integer value to search for
	 * @return the String name of the matching field.
	 */
	public static String toString(Class<?> clazz, int value) {
		return toString(clazz, Conv.intToLong(value));
	}

	/**
	 * Returns the field name of a final static variable in class <code>clazz</code>
	 * which holds a specific value.
	 * <p>
	 * Can be thought of as an enum numeric value to to name lookup.
	 * <p>
	 * @param clazz
	 * @param value
	 * @return
	 */
	public static String toString(Class<?> clazz, long value) {
		Field field = getStaticFinalFieldWithValue(clazz, value);
		return field != null ? field.getName()
				: "Unknown DWARF Value: 0x" + Long.toHexString(value);
	}

	/**
	 * Searches a Class for a final static variable that has a specific numeric value.
	 *
	 * @param clazz Class to search.
	 * @param value numeric value to search for
	 * @return Java reflection {@link Field} that has the specified value or null
	 */
	public static Field getStaticFinalFieldWithValue(Class<?> clazz, long value) {
		Field[] fields = clazz.getDeclaredFields();
		for (int i = 0; i < fields.length; i++) {
			if ((!Modifier.isFinal(fields[i].getModifiers())) ||
				(!Modifier.isStatic(fields[i].getModifiers()))) {
				continue;
			}
			try {
				long fieldValue = fields[i].getLong(null);
				if (fieldValue == value) {
					return fields[i];
				}
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				// ignore
			}
		}
		return null;
	}

	//--------------------------------------

	/**
	 * Returns a string that describes what kind of object is specified by the {@link DIEAggregate}.
	 * <p>
	 * Used to create a name for anonymous types.
	 *
	 * @param diea {@link DIEAggregate}
	 * @return String describing the type of the DIEA.
	 */
	public static String getContainerTypeName(DIEAggregate diea) {
		switch (diea.getTag()) {
			case DWARFTag.DW_TAG_structure_type:
				return "struct";
			case DWARFTag.DW_TAG_class_type:
				return "class";
			case DWARFTag.DW_TAG_enumeration_type:
				return "enum";
			case DWARFTag.DW_TAG_union_type:
				return "union";
			case DWARFTag.DW_TAG_lexical_block:
				return "lexical_block";
			case DWARFTag.DW_TAG_subprogram:
				return "subprogram";
			case DWARFTag.DW_TAG_subroutine_type:
				return "subr";
			case DWARFTag.DW_TAG_variable:
				return "var";
		}
		return "unknown";
	}

	//-------------------------------------------

	/**
	 * Returns the {@link SymbolType} that corresponds to the specified {@link DIEAggregate}.
	 * <p>
	 * The mapping between DIE type and SymbolType is not exact.  There is no matching
	 * SymbolType for a DWARF static variable, so "LOCAL_VAR" is used currently.
	 * <p>
	 * This mainly is used in constructing a NamespacePath, and the only critical usage
	 * there is Namespace vs. Class vs. everything else.
	 *
	 * @param diea {@link DIEAggregate} to query
	 * @return {@link SymbolType}
	 */
	public static SymbolType getSymbolTypeFromDIE(DIEAggregate diea) {
		switch (diea.getTag()) {

			case DWARFTag.DW_TAG_subprogram:
				return SymbolType.FUNCTION;

			case DWARFTag.DW_TAG_structure_type:
			case DWARFTag.DW_TAG_interface_type:
			case DWARFTag.DW_TAG_class_type:
			case DWARFTag.DW_TAG_union_type:
			case DWARFTag.DW_TAG_enumeration_type:
				return SymbolType.CLASS;

			case DWARFTag.DW_TAG_namespace:
				return SymbolType.NAMESPACE;
			default:
			case DWARFTag.DW_TAG_base_type:
			case DWARFTag.DW_TAG_typedef:
				return null;

			case DWARFTag.DW_TAG_formal_parameter:
				return SymbolType.PARAMETER;

			case DWARFTag.DW_TAG_variable:
				return SymbolType.LOCAL_VAR;
		}
	}

	private static Pattern MANGLED_NESTING_REGEX = Pattern.compile("(.*_Z)?N([0-9]+.*)");

	/**
	 * A lightweight attempt to get nesting (ie. namespaces and such) information
	 * from gnu mangled name strings.
	 * <p>
	 * For example, "_ZN19class1_inline_funcs3fooEv" -&gt;
	 * [19 chars]'class1_inline_funcs', [3 chars]'foo'
	 * <p>
	 * @param s
	 * @return
	 */
	public static List<String> parseMangledNestings(String s) {
		List<String> results = new ArrayList<>();
		Matcher m = MANGLED_NESTING_REGEX.matcher(s);
		if (!m.matches()) {
			return results;
		}
		s = m.group(2);

		int cp = 0;
		while (cp < s.length()) {
			int start = cp;
			while (Character.isDigit(s.charAt(cp)) && cp < s.length()) {
				cp++;
			}
			if (start == cp) {
				break;
			}
			int len = Integer.parseInt(s.substring(start, cp));
			if (cp + len <= s.length()) {
				String name = s.substring(cp, cp + len);
				results.add(name);
			}
			cp += len;
		}
		return results;
	}

	/**
	 * Try to find gnu mangled name nesting info in a DIE's children's linkage strings.
	 * <p>
	 * @param die
	 * @return a list of string of nesting names, ending with what should be the DIE parameter's
	 * name.
	 */
	public static List<String> findLinkageNameInChildren(DebugInfoEntry die) {
		DWARFProgram prog = die.getCompilationUnit().getProgram();
		for (DebugInfoEntry childDIE : die.getChildren(DWARFTag.DW_TAG_subprogram)) {
			DIEAggregate childDIEA = prog.getAggregate(childDIE);
			String linkage = childDIEA.getString(DWARFAttribute.DW_AT_linkage_name, null);
			if (linkage == null) {
				linkage = childDIEA.getString(DWARFAttribute.DW_AT_MIPS_linkage_name, null);
			}

			if (linkage != null) {
				List<String> nestings = parseMangledNestings(linkage);
				if (!nestings.isEmpty()) {
					nestings.remove(nestings.size() - 1);
					return nestings;
				}
			}
		}
		return Collections.EMPTY_LIST;
	}

	/**
	 * Determines if a name is a C++ style templated name.  If so, returns just
	 * the base portion of the name.
	 * The name must have a start and end angle bracket: '&lt;' and '&gt;'.
	 * <p>
	 * operator&lt;() and operator&lt;&lt;() are handled so their angle brackets
	 * don't trigger the template start/end angle bracket incorrectly.
	 * <p>
	 * @param name symbol name with C++ template portions
	 * @return base portion of the symbol name without template portion
	 */
	public static String getTemplateBaseName(String name) {
		int startOfTemplate =
			name.indexOf('<', name.startsWith(OPERATOR_LSHIFT_STR) ? OPERATOR_LSHIFT_STR.length()
					: name.startsWith(OPERATOR_LT_STR) ? OPERATOR_LT_STR.length() : 0);
		return (startOfTemplate > 0 && name.indexOf('>') > 0)
				? name.substring(0, startOfTemplate).trim()
				: null;
	}

	private static final String OPERATOR_LT_STR = "operator<";
	private static final String OPERATOR_LSHIFT_STR = "operator<<";

	/**
	 * Creates a name for anon types based on their position in their parent's childList.
	 * <p>
	 * @param diea the die aggregate.
	 * @return the anonymous name of the die aggregate.
	 */
	public static String getAnonNameForMeFromParentContext(DIEAggregate diea) {
		DebugInfoEntry parent = diea.getHeadFragment().getParent();
		if (parent == null) {
			return null;
		}

		DWARFProgram prog = diea.getProgram();
		int typeDefCount = 0;
		for (DebugInfoEntry childDIE : parent.getChildren()) {
			DIEAggregate childDIEA = prog.getAggregate(childDIE);
			if (diea == childDIEA) {
				return "anon_" + getContainerTypeName(childDIEA) + "_" + typeDefCount;
			}
			if (childDIEA.isNamedType()) {
				typeDefCount++;
			}
		}
		throw new RuntimeException("Could not find child in parent's list of children: child:\n" +
			diea + ",\nparent:\n" + parent);
	}

	/**
	 * Creates a name for anon types based on the names of sibling entries that are using the anon type.
	 * <p>
	 * Example: "anon_struct_for_field1_field2"
	 * <p>
	 * Falls back to {@link #getAnonNameForMeFromParentContext(DIEAggregate)} if no siblings found.
	 * @param diea the die aggregate.
	 * @return the anonymous name of the die aggregate.
	 */
	public static String getAnonNameForMeFromParentContext2(DIEAggregate diea) {
		DebugInfoEntry parent = diea.getHeadFragment().getParent();
		if (parent == null) {
			return null;
		}

		DWARFProgram prog = diea.getProgram();
		List<String> users = new ArrayList<>();
		for (DebugInfoEntry childDIE : parent.getChildren()) {
			DIEAggregate childDIEA = prog.getAggregate(childDIE);

			String childName = childDIEA.getName();
			DIEAggregate type = childDIEA.getTypeRef();
			if (type == diea && childName != null) {
				users.add(childName);
			}
		}
		Collections.sort(users);
		if (users.isEmpty()) {
			return getAnonNameForMeFromParentContext(diea);
		}

		StringBuilder sb = new StringBuilder();
		for (String childName : users) {
			if (sb.length() > 0) {
				sb.append("_");
			}
			sb.append(childName);
		}

		return "anon_" + getContainerTypeName(diea) + "_for_" + sb.toString();
	}

	/**
	 * Create a name for a lexical block, with "_" separated numbers indicating nesting
	 * information of the lexical block.
	 *
	 * @param diea {@link DIEAggregate} pointing to a lexical block entry.
	 * @return string, ie. "lexical_block_1_2_3"
	 */
	public static String getLexicalBlockName(DIEAggregate diea) {
		return "lexical_block" + getLexicalBlockNameWorker(diea.getHeadFragment());
	}

	private static String getLexicalBlockNameWorker(DebugInfoEntry die) {
		if (die.getTag() == DWARFTag.DW_TAG_lexical_block ||
			die.getTag() == DWARFTag.DW_TAG_inlined_subroutine) {
			return getLexicalBlockNameWorker(die.getParent()) + "_" +
				Integer.toString(getMyPositionInParent(die));
		}
		return "";
	}

	/**
	 * Returns the ordinal position of this {@link DebugInfoEntry} in it's parent.
	 *
	 * @param die {@link DebugInfoEntry}
	 * @return int index of ourself in our parent, or -1 if not found in parent.
	 */
	public static int getMyPositionInParent(DebugInfoEntry die) {
		DebugInfoEntry parent = die.getParent();
		if (parent != null) {
			int position = 0;
			for (DebugInfoEntry childDIE : parent.getChildren(die.getTag())) {
				if (childDIE == die) {
					return position;
				}
				position++;
			}
		}
		return -1;
	}

	/**
	 * Append a string to a {@link DataType}'s description.
	 *
	 * @param dt {@link DataType}
	 * @param description string to append, if null or empty nothing happens.
	 * @param sep characters to place after previous description to separate it from the
	 * new portion.
	 */
	public static void appendDescription(DataType dt, String description, String sep) {
		if (description == null || description.isEmpty()) {
			return;
		}
		String prev = dt.getDescription();
		if (prev == null) {
			prev = "";
		}
		if (!prev.isEmpty()) {
			prev += sep;
		}
		dt.setDescription(prev + description);
	}

	/**
	 * Append a string to a description of a field in a structure.
	 *
	 * @param dtc the {@link DataTypeComponent field} in a struct
	 * @param description string to append, if null or empty nothing happens.
	 * @param sep characters to place after previous description to separate it from the
	 * new portion.
	 */
	public static void appendDescription(DataTypeComponent dtc, String description, String sep) {
		if (description == null || description.isEmpty()) {
			return;
		}
		String prev = dtc.getComment();
		if (prev == null) {
			prev = "";
		}
		if (!prev.isEmpty()) {
			prev += sep;
		}
		dtc.setComment(prev + description);
	}

	/**
	 * Read an offset value who's size depends on the DWARF format: 32 vs 64.
	 * <p>
	 * @param reader BinaryReader pointing to the value to read
	 * @param dwarfFormat - See {@link DWARFCompilationUnit#DWARF_32} and {@link DWARFCompilationUnit#DWARF_64}.
	 * @return the offset value
	 * @throws IOException if an I/O error occurs or bad dwarfFormat value
	 */
	public static long readOffsetByDWARFformat(BinaryReader reader, int dwarfFormat)
			throws IOException {
		switch (dwarfFormat) {
			case DWARFCompilationUnit.DWARF_32:
				return reader.readNextUnsignedInt();
			case DWARFCompilationUnit.DWARF_64:
				return reader.readNextLong();
		}
		throw new IOException("Unknown DWARF Format Value: " + dwarfFormat);
	}

	/**
	 * Read a variable-sized unsigned integer and return it as a java signed long.
	 * <p>
	 * @param reader {@link BinaryReader} to read the data from
	 * @param pointerSize number of bytes the value is stored in, must be 1, 2, 4, or 8.
	 * @return unsigned long integer value.
	 * @throws IOException if error
	 */
	public static long readVarSizedULong(BinaryReader reader, int pointerSize) throws IOException {
		switch (pointerSize) {
			case 1:
				return reader.readNextUnsignedByte();
			case 2:
				return reader.readNextUnsignedShort();
			case 4:
				return reader.readNextUnsignedInt();
			case 8:
				return reader.readNextLong() /* no unsigned long mask possible */;
		}
		throw new IOException("Unsupported variable-sized int: " + pointerSize);
	}

	/**
	 * Read a variable-sized unsigned integer and return it as a java signed int.
	 * <p>
	 * Unsigned 32 bit int values larger than java's signed Integer.MAX_VALUE are not
	 * supported and will throw an IOException.
	 *
	 * @param reader {@link BinaryReader} to read the data from
	 * @param size number of bytes the integer value is stored in, must be 1, 2 or 4.
	 * @return unsigned integer value.
	 * @throws IOException if error
	 */
	public static int readVarSizedUInt(BinaryReader reader, int size) throws IOException {
		switch (size) {
			case 1:
				return reader.readNextUnsignedByte();
			case 2:
				return reader.readNextUnsignedShort();
			case 4:
				long l = reader.readNextUnsignedInt();
				if (l < 0 || l > Integer.MAX_VALUE) {
					throw new IOException("Unsigned int value too large: " + l);
				}
				return (int) l;
		}
		throw new IOException("Unsupported variable-sized int: " + size);
	}

	/**
	 * Read the value of an address.
	 * @param reader BinaryReader pointing to the value to read
	 * @param pointerSize the size of a pointer
	 * @return the address value
	 * @throws IOException if an I/O error occurs
	 * @throws IllegalArgumentException if an unknown pointer size is given
	 */
	public static Number readAddress(BinaryReader reader, byte pointerSize) throws IOException {
		switch (pointerSize) {
			case 1:
				return Byte.valueOf(reader.readNextByte());
			case 2:
				return Short.valueOf(reader.readNextShort());
			case 4:
				return Integer.valueOf(reader.readNextInt());
			case 8:
				return Long.valueOf(reader.readNextLong());
		}
		throw new IllegalArgumentException(
			"Unknown pointer size: 0x" + Integer.toHexString(pointerSize));
	}

	/**
	 * Reads a variable-sized unsigned 'address' value from a {@link BinaryReader} and
	 * returns it as a 64 bit java long.
	 * <p>
	 * The valid pointerSizes are 1, 2, 4, and 8.
	 * <p>
	 * @param reader {@link BinaryReader} to read the data from
	 * @param pointerSize number of bytes the value is stored in, must be 1, 2, 4, or 8.
	 * @return unsigned long value.
	 * @throws IOException if error
	 */
	public static long readAddressAsLong(BinaryReader reader, byte pointerSize) throws IOException {
		switch (pointerSize) {
			case 1:
				return reader.readNextUnsignedByte();
			case 2:
				return reader.readNextUnsignedShort();
			case 4:
				return reader.readNextUnsignedInt();
			case 8:
				return reader.readNextLong();
		}
		throw new IllegalArgumentException(
			"Unknown pointer size: 0x" + Integer.toHexString(pointerSize));
	}

	public static boolean isThisParam(DIEAggregate paramDIEA) {
		// DWARF has multiple ways of indicating a DW_TAG_formal_parameter is
		// the "this" parameter, and different versions of different toolchains
		// can express this differently.
		// We check the most common method (param named "this" or marked artificial) first,
		// and then check the object_pointer property of the parent function.
		//
		// DW_AT_artificial indicates that the param was not declared in the source but
		// was added 'behind the scenes', and a "this" param is the main example of this.
		//
		// A DW_AT_object_pointer property in the parent function is an explict way of
		// referencing the param that points to the object instance (ie. "this").
		//
		if (paramDIEA.getBool(DWARFAttribute.DW_AT_artificial, false) ||
			"this".equals(paramDIEA.getName())) {
			return true;
		}

		DWARFAttributeValue dwATObjectPointer =
			paramDIEA.getParent().getAttribute(DWARFAttribute.DW_AT_object_pointer);
		return dwATObjectPointer != null && dwATObjectPointer instanceof DWARFNumericAttribute &&
			paramDIEA.hasOffset(((DWARFNumericAttribute) dwATObjectPointer).getUnsignedValue());
	}

	/**
	 * Returns the {@link DIEAggregate} of a typedef that points to the specified datatype.
	 * <p>
	 * Returns null if there is no typedef pointing to the specified DIEA or if there are
	 * multiple.
	 *
	 * @param diea {@link DIEAggregate} of a data type that might be the target of typedefs.
	 * @return {@link DIEAggregate} of the singular typedef that points to the arg, otherwise
	 * null if none or multiple found.
	 */
	public static DIEAggregate getReferringTypedef(DIEAggregate diea) {
		if (diea == null) {
			return null;
		}
		List<DIEAggregate> referers =
			diea.getProgram().getTypeReferers(diea, DWARFTag.DW_TAG_typedef);
		return (referers.size() == 1) ? referers.get(0) : null;
	}

	public static class LengthResult {
		public final long length;
		public final int format;	// either DWARF_32 or DWARF_64

		private LengthResult(long length, int format) {
			this.length = length;
			this.format = format;
		}
	}

	/**
	 * Read a variable-length length value from the stream.
	 * <p>
	 * 
	 * @param reader {@link BinaryReader} stream to read from
	 * @param program Ghidra {@link Program} 
	 * @return new {@link LengthResult}, never null; length == 0 should be checked for and treated
	 * specially
	 * @throws IOException if io error
	 * @throws DWARFException if invalid values
	 */
	public static LengthResult readLength(BinaryReader reader, Program program)
			throws IOException, DWARFException {
		long length = reader.readNextUnsignedInt();
		int format;

		if (length == 0xffffffffL) {
			// Length of 0xffffffff implies 64-bit DWARF format
			// Mostly untested as there is no easy way to force the compiler
			// to generate this
			length = reader.readNextLong();
			format = DWARFCompilationUnit.DWARF_64;
		}
		else if (length >= 0xfffffff0L) {
			// Length of 0xfffffff0 or greater is reserved for DWARF
			throw new DWARFException("Reserved DWARF length value: " + Long.toHexString(length) +
				". Unknown extension.");
		}
		else if (length == 0) {
			// Test for special case of weird BE MIPS 64bit length value.
			// Instead of following DWARF std (a few lines above with length == MAX_INT),
			// it writes a raw 64bit long (BE). The upper 32 bits (already read as length) will 
			// always be 0 since super-large binaries from that system weren't really possible.
			// The next 32 bits will be the remainder of the value.
			if ( reader.isBigEndian() && program.getDefaultPointerSize() == 8) {
				length = reader.readNextUnsignedInt();
				format = DWARFCompilationUnit.DWARF_64;
			}
			else {
				// length 0 signals an error to caller
				format = DWARFCompilationUnit.DWARF_32; // doesn't matter
			}
		}
		else {
			format = DWARFCompilationUnit.DWARF_32;
		}

		return new LengthResult(length, format);
	}

}
