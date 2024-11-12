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
package ghidra.app.util.bin.format.dwarf;

import static ghidra.app.util.bin.format.dwarf.DWARFTag.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.*;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;
import ghidra.app.cmd.comments.AppendCommentCmd;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeValue;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionException;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;

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
		return toString(clazz, Integer.toUnsignedLong(value));
	}

	/**
	 * Returns the field name of a final static variable in class <code>clazz</code>
	 * which holds a specific value.
	 * <p>
	 * Can be thought of as an enum numeric value to to name lookup.
	 * 
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





	private static Pattern MANGLED_NESTING_REGEX = Pattern.compile("(.*_Z)?N([0-9]+.*)");

	/**
	 * A lightweight attempt to get nesting (ie. namespaces and such) information
	 * from gnu mangled name strings.
	 * <p>
	 * For example, "_ZN19class1_inline_funcs3fooEv" -&gt;
	 * [19 chars]'class1_inline_funcs', [3 chars]'foo'
	 * 
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
	 * 
	 * @param die
	 * @return a list of string of nesting names, ending with what should be the DIE parameter's
	 * name.
	 */
	public static List<String> findLinkageNameInChildren(DebugInfoEntry die) {
		DWARFProgram prog = die.getProgram();
		for (DebugInfoEntry childDIE : die.getChildren(DWARFTag.DW_TAG_subprogram)) {
			DIEAggregate childDIEA = prog.getAggregate(childDIE);
			String linkage = childDIEA.getString(DW_AT_linkage_name, null);
			if (linkage == null) {
				linkage = childDIEA.getString(DW_AT_MIPS_linkage_name, null);
			}

			if (linkage != null) {
				List<String> nestings = parseMangledNestings(linkage);
				if (!nestings.isEmpty()) {
					nestings.remove(nestings.size() - 1);
					return nestings;
				}
			}
		}
		return List.of();
	}

	/**
	 * Determines if a name is a C++ style templated name.  If so, returns just
	 * the base portion of the name.
	 * The name must have a start and end angle bracket: '&lt;' and '&gt;'.
	 * <p>
	 * operator&lt;() and operator&lt;&lt;() are handled so their angle brackets
	 * don't trigger the template start/end angle bracket incorrectly.
	 * 
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
	 * 
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
			if (diea == childDIEA || diea.getOffset() == childDIEA.getOffset()) {
				return "anon_%s_%d".formatted(childDIEA.getTag().getContainerTypeName(),
					typeDefCount);
			}
			if (childDIEA.getTag().isNamedType()) {
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

		return "anon_" + diea.getTag().getContainerTypeName() + "_for_" + sb.toString();
	}

	/**
	 * Creates a fingerprint of the layout of an (anonymous) structure using its
	 * size, number of members, and the hashcode of the member field names.
	 * 
	 * @param diea struct/union/class
	 * @return formatted string, example "80_5_73dc6de9" (80 bytes, 5 fields, hex hash of field names) 
	 */
	public static String getStructLayoutFingerprint(DIEAggregate diea) {
		long structSize = diea.getUnsignedLong(DW_AT_byte_size, 0);
		int memberCount = 0;
		List<String> memberNames = new ArrayList<>();
		for (DebugInfoEntry childEntry : diea.getHeadFragment().getChildren()) {
			if (!(childEntry.getTag() == DWARFTag.DW_TAG_member ||
				childEntry.getTag() == DWARFTag.DW_TAG_inheritance)) {
				continue;
			}
			DIEAggregate childDIEA = diea.getProgram().getAggregate(childEntry);
			if (childDIEA.hasAttribute(DW_AT_external)) {
				continue;
			}
			memberCount++;

			String memberName = childDIEA.getName();
			int memberOffset = 0;
			try {
				memberOffset =
					childDIEA.parseDataMemberOffset(DW_AT_data_member_location, 0);
			}
			catch (DWARFExpressionException | IOException e) {
				// ignore, leave as default value 0
			}
			if (memberName == null) {
				memberName = "UNNAMED_MEMBER_" + memberCount;
			}
			memberName = String.format("%04x_%s", memberOffset, memberName);
			memberNames.add(memberName);
		}
		Collections.sort(memberNames);	// "hexoffset_name"
		return String.format("%d_%d_%08x", structSize, memberCount, memberNames.hashCode());
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

	public static void appendComment(Program program, Address address, CommentType commentType,
			String prefix, String comment, String sep) {
		if (comment == null || comment.isBlank()) {
			return;
		}
		CodeUnit cu = getCodeUnitForComment(program, address);
		if (cu != null) {
			String existingComment = cu.getComment(commentType);
			if (existingComment != null && existingComment.contains(comment)) {
				// don't add same comment twice
				return;
			}
		}
		AppendCommentCmd cmd = new AppendCommentCmd(address, commentType.ordinal(),
			Objects.requireNonNullElse(prefix, "") + comment, sep);
		cmd.applyTo(program);
	}

	public static CodeUnit getCodeUnitForComment(Program program, Address address) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu == null) {
			return null;
		}
		Address cuAddr = cu.getMinAddress();
		if (cu instanceof Data && !address.equals(cuAddr)) {
			Data data = (Data) cu;
			return data.getPrimitiveAt((int) address.subtract(cuAddr));
		}
		return cu;
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
		String paramName = paramDIEA.getName();
		if (paramDIEA.getBool(DW_AT_artificial, false) ||
			Function.THIS_PARAM_NAME.equals(paramName)) {
			return true;
		}

		DIEAggregate funcDIEA = paramDIEA.getParent();
		DWARFAttributeValue dwATObjectPointer =
			funcDIEA.getAttribute(DW_AT_object_pointer);
		if (dwATObjectPointer != null && dwATObjectPointer instanceof DWARFNumericAttribute dnum &&
			paramDIEA.hasOffset(dnum.getUnsignedValue())) {
			return true;
		}

		// If the variable is not named, check to see if the parent of the function
		// is a struct/class, and the parameter points to it
		DIEAggregate classDIEA = funcDIEA.getParent();
		if (paramName == null && classDIEA != null && classDIEA.getTag().isStructureType()) {
			// Check to see if the parent data type equals the parameters' data type
			return isPointerTo(classDIEA, paramDIEA.getTypeRef());
		}

		return false;
	}

	public static boolean isPointerTo(DIEAggregate targetDIEA, DIEAggregate testDIEA) {
		return testDIEA != null && testDIEA.getTag() == DW_TAG_pointer_type &&
			testDIEA.getTypeRef() == targetDIEA;
	}

	public static boolean isPointerDataType(DIEAggregate diea) {
		while (diea.getTag() == DW_TAG_typedef) {
			diea = diea.getTypeRef();
		}
		return diea.getTag() == DW_TAG_pointer_type;
	}

	/**
	 * Returns a file that has been referenced in the specified {@link Language language's}
	 * ldefs description via a
	 * <pre>&lt;external_name tool="<b>name</b>" name="<b>value</b>"/&gt;</pre>
	 * entry.
	 *  
	 * @param lang {@link Language} to query
	 * @param name name of the option in the ldefs file
	 * @return file pointed to by the specified external_name tool entry 
	 * @throws IOException if not a sleigh lang
	 */
	public static ResourceFile getLanguageExternalFile(Language lang, String name)
			throws IOException {
		String filename = getLanguageExternalNameValue(lang, name);
		return filename != null
				? new ResourceFile(getLanguageDefinitionDirectory(lang), filename)
				: null;
	}

	/**
	 * Returns the base directory of a language definition.
	 * 
	 * @param lang {@link Language} to get base definition directory
	 * @return base directory for language definition files
	 * @throws IOException if not a sleigh lang
	 */
	public static ResourceFile getLanguageDefinitionDirectory(Language lang) throws IOException {
		LanguageDescription langDesc = lang.getLanguageDescription();
		if (!(langDesc instanceof SleighLanguageDescription sld)) {
			throw new IOException("Not a Sleigh Language: " + lang.getLanguageID());
		}
		ResourceFile defsFile = sld.getDefsFile();
		ResourceFile parentFile = defsFile.getParentFile();
		return parentFile;
	}

	/**
	 * Returns a value specified in a {@link Language} definition via a
	 * <pre>&lt;external_name tool="<b>name</b>" name="<b>value</b>"/&gt;</pre>
	 * entry.
	 * 
	 * @param lang {@link Language} to query
	 * @param name name of the value
	 * @return String value
	 * @throws IOException
	 */
	public static String getLanguageExternalNameValue(Language lang, String name)
			throws IOException {
		LanguageDescription langDesc = lang.getLanguageDescription();
		if (!(langDesc instanceof SleighLanguageDescription)) {
			throw new IOException("Not a Sleigh Language: " + lang.getLanguageID());
		}
		List<String> values = langDesc.getExternalNames(name);
		if (values == null || values.isEmpty()) {
			return null;
		}
		if (values.size() > 1) {
			throw new IOException(
				String.format("Multiple external name values for %s found in language %s", name,
					lang.getLanguageID()));
		}
		return values.get(0);
	}

	public static void packCompositeIfPossible(Composite original, DataTypeManager dtm) {
		if (original.isZeroLength() || original.getNumComponents() == 0) {
			// don't try to pack empty structs, this would throw off conflicthandler logic.
			// also don't pack sized structs with no fields because when packed down to 0 bytes they
			// cause errors when used as a param type
			return;
		}

		Composite copy = (Composite) original.copy(dtm);
		copy.setToDefaultPacking();
		if (copy.getLength() != original.getLength()) {
			// so far, typically because trailing zero-len flex array caused toolchain to
			// bump struct size to next alignment value in a way that doesn't mesh with ghidra's
			// logic
			return;  // fail
		}

		DataTypeComponent[] preComps = original.getDefinedComponents();
		DataTypeComponent[] postComps = copy.getDefinedComponents();
		if (preComps.length != postComps.length) {
			return; // fail
		}
		for (int index = 0; index < preComps.length; index++) {
			DataTypeComponent preDTC = preComps[index];
			DataTypeComponent postDTC = postComps[index];
			if (preDTC.getOffset() != postDTC.getOffset() ||
				preDTC.getLength() != postDTC.getLength() ||
				preDTC.isBitFieldComponent() != postDTC.isBitFieldComponent()) {
				return;  // fail
			}
			if (preDTC.isBitFieldComponent()) {
				BitFieldDataType preBFDT = (BitFieldDataType) preDTC.getDataType();
				BitFieldDataType postBFDT = (BitFieldDataType) postDTC.getDataType();
				if (preBFDT.getBitOffset() != postBFDT.getBitOffset() ||
					preBFDT.getBitSize() != postBFDT.getBitSize()) {
					return;  // fail
				}
			}
		}

		original.setToDefaultPacking();
	}

	public static List<Varnode> convertRegisterListToVarnodeStorage(List<Register> registers,
			int dataTypeSize) {
		List<Varnode> results = new ArrayList<>();
		for (Register reg : registers) {
			int regSize = reg.getMinimumByteSize();
			int bytesUsed = Math.min(dataTypeSize, regSize);
			Address addr = reg.getAddress();
			if (reg.isBigEndian() && bytesUsed < regSize) {
				addr = addr.add(regSize - bytesUsed);
			}
			results.add(new Varnode(addr, bytesUsed));
			dataTypeSize -= bytesUsed;
		}
		return results;
	}

	public static boolean isEmptyArray(DataType dt) {
		return dt instanceof Array array && array.getNumElements() == 0;
	}

	public static boolean isZeroByteDataType(DataType dt) {
		if (VoidDataType.dataType.isEquivalent(dt)) {
			return true;
		}
		if (!dt.isZeroLength() && dt instanceof Array) {
			dt = DataTypeUtilities.getArrayBaseDataType((Array) dt);
		}
		return dt.isZeroLength();
	}

	public static boolean isVoid(DataType dt) {
		return VoidDataType.dataType.isEquivalent(dt);
	}

	public static boolean isStackVarnode(Varnode varnode) {
		return varnode != null &&
			varnode.getAddress().getAddressSpace().getType() == AddressSpace.TYPE_STACK;
	}

}
