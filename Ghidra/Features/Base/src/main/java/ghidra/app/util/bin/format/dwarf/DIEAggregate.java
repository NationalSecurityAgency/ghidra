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
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeId.*;

import java.io.IOException;
import java.util.*;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.util.bin.format.dwarf.attribs.*;
import ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionEvaluator;
import ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.dwarf.line.DWARFFile;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine;
import ghidra.util.Msg;

/**
 * DIEAggregate groups related {@link DebugInfoEntry} records together in a single interface
 * for querying attribute values.
 * <p>
 * Information about program elements are written into the .debug_info as partial snapshots
 * of the element, with later follow-up records that more fully specify the program element.
 * <p>
 * (For instance, a declaration-only DIE that introduces the name of a structure type
 * will be found at the beginning of a compilation unit, followed later by a DIE that
 * specifies the contents of the structure type)
 * <p>
 * A DIEAggregate groups these {@link DebugInfoEntry} records under one interface so a fully
 * specified view of the program element can be presented.
 */
public class DIEAggregate {

	/**
	 * Sanity check upper limit on how many DIE records can be in a aggregate.
	 */
	private static final int MAX_FRAGMENT_COUNT = 20;

	/**
	 * A list of {@link DebugInfoEntry DIEs} that make up this DWARF program element, with
	 * the 'head'-most listed first, followed by earlier less specified DIEs, ending with
	 * the first 'decl' DIE in the last element.
	 * <p>
	 * For example:<p>
	 * [0] - head<br>
	 * [1] - specification<br>
	 * [2] - decl<br>
	 * <p>
	 * A primitive array is used instead of a java.util.List because of memory constraint issues
	 * and also that the set of fragments does not change after the bootstrap process in
	 * {@link #createFromHead(DebugInfoEntry) createFromHead()}.
	 */
	private DebugInfoEntry[] fragments;

	/**
	 * Creates a {@link DIEAggregate} starting from a 'head' {@link DebugInfoEntry} instance.
	 * <p>
	 * DW_AT_abstract_origin and DW_AT_specification attributes are followed to find the previous
	 * {@link DebugInfoEntry} instances.
	 * 
	 * @param die starting DIE record
	 * @return new {@link DIEAggregate} made up of the starting DIE and all DIEs that it points
	 * to via abstract_origin and spec attributes.
	 */
	public static DIEAggregate createFromHead(DebugInfoEntry die) {
		// build the list of fragments assuming we are starting at the topmost fragment
		// (ie. forward references only).
		// Possible fragments are:
		//   headEntry --abstract_origin--> specEntry --specification--> declEntry
		// The fragments are in reversed order (ie. more primitive DIEs are at the
		// front of the list) while querying for additional abstract_origin
		// values to ensure that we retrieve what would normally be the overridden value.
		// When all fragments have been found, the order of the fragments is reversed so
		// that the 'head' or topmost fragment is first in the list and will be the DIE record
		// queried first for attribute values.

		DIEAggregate result = new DIEAggregate(new DebugInfoEntry[] { die });

		// keep querying for abstract_origin DIEs as long as we haven't seen them yet,
		// and add them to the fragment list.
		DebugInfoEntry tmp;
		while ((tmp = result.getRefDIE(DW_AT_abstract_origin)) != null &&
			!result.hasOffset(tmp.getOffset()) && result.getFragmentCount() < MAX_FRAGMENT_COUNT) {
			result.addFragment(tmp);
		}

		// look for 1 spec DIE and add it.
		tmp = result.getRefDIE(DW_AT_specification);
		if (tmp != null) {
			result.addFragment(tmp);
		}
		result.flipFragments();
		return result;
	}

	/**
	 * Creates a new {@link DIEAggregate} from the contents of the specified DIEA, using
	 * all the source's {@link DebugInfoEntry} fragments except for the head fragment
	 * which is skipped.
	 * <p>
	 * Used when a DIEA is composed of a head DIE with a different TAG type than the rest of
	 * the DIEs.  (ie. a dw_tag_call_site -&gt; dw_tag_sub DIEA)
	 *
	 * @param source {@link DIEAggregate} containing fragments
	 * @return {@link DIEAggregate} with the fragments of the source, skipping the first
	 */
	public static DIEAggregate createSkipHead(DIEAggregate source) {
		if (source.fragments.length == 1) {
			return null;
		}
		DebugInfoEntry[] partialFrags = new DebugInfoEntry[source.fragments.length - 1];
		System.arraycopy(source.fragments, 1, partialFrags, 0, partialFrags.length);
		return new DIEAggregate(partialFrags);
	}

	/**
	 * Create a {@link DIEAggregate} from a single {@link DebugInfoEntry DIE}.
	 * <p>
	 * Mainly useful early in the {@link DWARFCompilationUnit}'s bootstrapping process
	 * when it needs to read values from DIEs.
	 * 
	 * @param die {@link DebugInfoEntry}
	 * @return {@link DIEAggregate} containing a single DIE
	 */
	public static DIEAggregate createSingle(DebugInfoEntry die) {
		DIEAggregate result = new DIEAggregate(new DebugInfoEntry[] { die });

		return result;
	}

	/**
	 * Private ctor to force use of the static factory methods {@link #createFromHead(DebugInfoEntry)}
	 * and {@link #createSingle(DebugInfoEntry)}.
	 * 
	 * @param fragments array of DIEs that make this aggregate
	 */
	private DIEAggregate(DebugInfoEntry[] fragments) {
		this.fragments = fragments;
	}

	/**
	 * Used during creation process to add new DebugInfoEntry elements as they are found by
	 * following links in the current set of DIEs.
	 * <p>
	 * Adds the new DIE fragment to the front of the fragment array list, which is reversed
	 * from how it needs to be when this DIEA is being used.  The caller needs to
	 * call {@link #flipFragments()} after the build phase to reverse the order of the
	 * DIE fragments list so that querying for attribute values will return the correct values.
	 *
	 * @param newDIE {@link DebugInfoEntry} to add
	 */
	private void addFragment(DebugInfoEntry newDIE) {
		DebugInfoEntry[] tmp = new DebugInfoEntry[fragments.length + 1];
		System.arraycopy(fragments, 0, tmp, 1, fragments.length);
		tmp[0] = newDIE;
		fragments = tmp;
	}

	private void flipFragments() {
		ArrayUtils.reverse(fragments);
	}

	public int getFragmentCount() {
		return fragments.length;
	}

	public long getOffset() {
		return getHeadFragment().getOffset();
	}

	public long[] getOffsets() {
		long[] result = new long[fragments.length];
		for (int i = 0; i < fragments.length; i++) {
			result[i] = fragments[i].getOffset();
		}
		return result;
	}

	/**
	 * Returns true if any of the {@link DebugInfoEntry DIEs} that makeup this aggregate
	 * have the specified offset.
	 *
	 * @param offset DIE offset to search for
	 * @return true if this {@link DIEAggregate} has a fragment DIE at that offset.
	 */
	public boolean hasOffset(long offset) {
		for (DebugInfoEntry fragment : fragments) {
			if (fragment.getOffset() == offset) {
				return true;
			}
		}
		return false;
	}

	public long getDeclOffset() {
		return getLastFragment().getOffset();
	}

	/**
	 * Returns {@link #getOffset()} as a hex string.
	 * @return string hex offset of the head DIE
	 */
	public String getHexOffset() {
		return Long.toHexString(getHeadFragment().getOffset());
	}

	public DWARFTag getTag() {
		return getHeadFragment().getTag();
	}

	public DWARFCompilationUnit getCompilationUnit() {
		return getHeadFragment().getCompilationUnit();
	}

	public DWARFProgram getProgram() {
		return getHeadFragment().getProgram();
	}

	/**
	 * Returns the last {@link DebugInfoEntry DIE} fragment, ie. the decl DIE.
	 * @return last DIE of this aggregate
	 */
	public DebugInfoEntry getLastFragment() {
		return fragments[fragments.length - 1];
	}

	/**
	 * Returns the first {@link DebugInfoEntry DIE} fragment, ie. the spec or abstract_origin
	 * DIE.
	 * @return first DIE of this aggregate
	 */
	public DebugInfoEntry getHeadFragment() {
		return fragments[0];
	}

	public DIEAggregate getDeclParent() {
		DebugInfoEntry declDIE = getLastFragment();
		DebugInfoEntry declParent = declDIE.getParent();
		return getProgram().getAggregate(declParent);
	}

	public DIEAggregate getParent() {
		DebugInfoEntry die = getHeadFragment();
		DebugInfoEntry parent = die.getParent();
		return getProgram().getAggregate(parent);
	}

	/**
	 * Returns the depth of the head fragment, where depth is defined as
	 * the distance between the DIE and the root DIE of the owning compilation
	 * unit.
	 * <p>
	 * The root die would return 0, the children of the root will return 1, etc.
	 * <p>
	 * This value matches the nesting value shown when dumping DWARF
	 * info using 'readelf'.
	 *
	 * @return depth of this instance, from the root of its head DIE fragment, with 0 indicating
	 * that this instance was already the root of the compUnit  
	 */
	public int getDepth() {
		return getProgram().getParentDepth(getHeadFragment().getIndex());
	}

	/**
	 * Return an attribute that is present in this {@link DIEAggregate}, or in any of its
	 * direct children (of a specific type)
	 *  
	 * @param <T> attribute value type
	 * @param attrId the attribute to find
	 * @param childTag the type of children to search
	 * @param clazz type of the attribute to return
	 * @return attribute value, or null if not found
	 */
	public <T extends DWARFAttributeValue> T findAttributeInChildren(DWARFAttributeId attrId,
			DWARFTag childTag, Class<T> clazz) {
		T attributeValue = findValue(attrId, clazz);
		if (attributeValue != null) {
			return attributeValue;
		}
		for (DebugInfoEntry childDIE : getChildren(childTag)) {
			DIEAggregate childDIEA = getProgram().getAggregate(childDIE);
			attributeValue = childDIEA.findValue(attrId, clazz);
			if (attributeValue != null) {
				return attributeValue;
			}
		}
		return null;
	}

	/**
	 * {@return the matching attribute, by id, or null if not found}
	 * @param attrId {@link DWARFAttributeId} DW_AT_xyz
	 */
	public DWARFAttribute findAttribute(DWARFAttributeId attrId) {
		for (DebugInfoEntry die : fragments) {
			DWARFAttribute attr = die.findAttribute(attrId);
			if (attr != null) {
				return attr;
			}
		}
		return null;
	}

	/**
	 * Finds a {@link DWARFAttributeValue attribute value} with a matching 
	 * {@link DWARFAttributeId} id.
	 * <p>
	 * Returns null if the attribute does not exist or is wrong java class type.
	 * <p>
	 * Attributes are searched for in each fragment in this aggregate, starting with the
	 * 'head' fragment, progressing toward the 'decl' fragment.
	 *
	 * @param attrId See {@link DWARFAttributeId}
	 * @param valueClass must be derived from {@link DWARFAttributeValue}
	 * @return DWARFAttributeValue or subclass as specified by the valueClass, or null if not found
	 */
	public <T extends DWARFAttributeValue> T findValue(DWARFAttributeId attrId,
			Class<T> valueClass) {
		DWARFAttribute attr = findAttribute(attrId);
		return attr != null ? attr.getValue(valueClass) : null;
	}

	/**
	 * Finds a {@link DWARFAttributeValue attribute value} with a matching
	 * {@link DWARFAttributeId} id.
	 * <p>
	 * Returns null if the attribute does not exist.
	 * <p>
	 * Attributes are searched for in each fragment in this aggregate, starting with the
	 * 'head' fragment, progressing toward the 'decl' fragment.
	 *
	 * @param attrId See {@link DWARFAttributeId}
	 * @return DWARFAttributeValue, or null if not found
	 */
	public DWARFAttributeValue findValue(DWARFAttributeId attrId) {
		return findValue(attrId, DWARFAttributeValue.class);
	}

	/**
	 * Returns the value of the requested attribute, or -defaultValue- if the
	 * attribute is missing.
	 *
	 * @param attrId {@link DWARFAttributeId} id
	 * @param defaultValue value to return if attribute is not present
	 * @return long value, or the defaultValue if attribute not present
	 */
	public long getLong(DWARFAttributeId attrId, long defaultValue) {
		DWARFNumericAttribute attr = findValue(attrId, DWARFNumericAttribute.class);
		return (attr != null) ? attr.getValue() : defaultValue;
	}

	/**
	 * Returns the boolean value of the requested attribute, or -defaultValue- if
	 * the attribute is missing or not the correct type.
	 * 
	 * @param attrId {@link DWARFAttributeId} id
	 * @param defaultValue value to return if attribute is not present
	 * @return boolean value, or the defaultValue if attribute is not present
	 */
	public boolean getBool(DWARFAttributeId attrId, boolean defaultValue) {
		DWARFBooleanAttribute val = findValue(attrId, DWARFBooleanAttribute.class);
		return (val != null) ? val.getValue() : defaultValue;
	}

	/**
	 * Returns the string value of the requested attribute, or -defaultValue- if
	 * the attribute is missing or not the correct type.
	 * 
	 * @param attrId {@link DWARFAttributeId} id
	 * @param defaultValue value to return if attribute is not present
	 * @return String value, or the defaultValue if attribute is not present
	 */
	public String getString(DWARFAttributeId attrId, String defaultValue) {
		DWARFAttribute attr = findAttribute(attrId);
		return attr != null && attr.getValue() instanceof DWARFStringAttribute sval
				? sval.getValue(attr.getDIE().getCompilationUnit())
				: defaultValue;
	}

	/**
	 * Returns the string value of the {@link DWARFAttributeId#DW_AT_name DW_AT_name} attribute,
	 * or null if it is missing.
	 * 
	 * @return name of this DIE aggregate, or null if missing
	 */
	public String getName() {
		return getString(DW_AT_name, null);
	}

	/**
	 * Returns the unsigned long integer value of the requested attribute, or -defaultValue-
	 * if the attribute is missing.
	 * <p>
	 * The 'unsigned'ness of this method refers to how the binary value is read from
	 * the dwarf information (ie. a value with the high bit set is not treated as signed).
	 * <p>
	 * The -defaultValue- parameter can accept a negative value.
	 * 
	 * @param attrId {@link DWARFAttributeId} id
	 * @param defaultValue value to return if attribute is not present
	 * @return unsigned long value, or the defaultValue if attribute is not present
	 */
	public long getUnsignedLong(DWARFAttributeId attrId, long defaultValue) {
		DWARFNumericAttribute attr = findValue(attrId, DWARFNumericAttribute.class);
		return (attr != null) ? attr.getUnsignedValue() : defaultValue;
	}

	private DebugInfoEntry getRefDIE(DWARFAttributeId attrId) {
		DWARFAttribute foundAttr = findAttribute(attrId);
		if (foundAttr == null || !(foundAttr.getValue() instanceof DWARFNumericAttribute val)) {
			return null;
		}

		try {
			return getProgram().getDIE(foundAttr.getAttributeForm(), val.getUnsignedValue(),
				foundAttr.getDIE().getCompilationUnit());
		}
		catch (IOException e) {
			Msg.warn(this, "Invalid reference from DIE 0x%x to 0x%x (%s)".formatted(
				foundAttr.getDIE().getOffset(), val.getUnsignedValue(),
				foundAttr.getAttributeForm()));
			Msg.debug(this, this.toString());
		}
		return null;
	}

	/**
	 * Returns the {@link DIEAggregate diea} instance pointed to by the requested attribute,
	 * or null if the attribute does not exist.
	 * 
	 * @param attrId {@link DWARFAttributeId} id
	 * @return {@link DIEAggregate}, or the null if attribute is not present
	 */
	public DIEAggregate getRef(DWARFAttributeId attrId) {
		DebugInfoEntry die = getRefDIE(attrId);
		return getProgram().getAggregate(die);
	}

	/**
	 * Returns the DIE pointed to by a DW_AT_containing_type attribute.
	 *
	 * @return DIEA pointed to by the DW_AT_containing_type attribute, or null if not present.
	 */
	public DIEAggregate getContainingTypeRef() {
		return getRef(DW_AT_containing_type);
	}

	public DIEAggregate getTypeRef() {
		return getRef(DW_AT_type);
	}

	/**
	 * Returns the name of the source file this item was declared in (DW_AT_decl_file)
	 * 
	 * @return name of file this item was declared in, or null if info not available
	 */
	public String getSourceFile() {
		DWARFAttribute attrInfo = findAttribute(DW_AT_decl_file);
		if (attrInfo == null) {
			return null;
		}
		DWARFNumericAttribute attr = attrInfo.getValue(DWARFNumericAttribute.class);
		if (attr == null) {
			return null;
		}
		try {
			int fileNum = attr.getUnsignedIntExact();
			DWARFLine line = attrInfo.getDIE().getCompilationUnit().getLine();
			DWARFFile file = line.getFile(fileNum);
			return file.getName();
		}
		catch (IOException e) {
			return null;
		}
	}

	/**
	 * Return a list of children that are of a specific DWARF type.
	 * 
	 * @param childTag see {@link DWARFTag DWARFTag DW_TAG_* values}
	 * @return List of children DIEs that match the specified tag
	 */
	public List<DebugInfoEntry> getChildren(DWARFTag childTag) {
		return getHeadFragment().getChildren(childTag);
	}

	/**
	 * Returns true if the specified attribute is present.
	 * 
	 * @param attrId attribute id
	 * @return boolean true if value is present
	 */
	public boolean hasAttribute(DWARFAttributeId attrId) {
		return findAttribute(attrId) != null;
	}

	/**
	 * Return a {@link DIEAggregate} that only contains the information present in the
	 * "abstract instance" (and lower) DIEs.
	 * 
	 * @return a new {@link DIEAggregate}, or null if this DIEA was not split into a concrete and
	 * abstract portion
	 */
	public DIEAggregate getAbstractInstance() {
		DWARFAttribute aoAttr = findAttribute(DW_AT_abstract_origin);
		if (aoAttr == null) {
			return null;
		}
		for (int aoIndex = 0; aoIndex < fragments.length; aoIndex++) {
			if (fragments[aoIndex] == aoAttr.getDIE()) {
				DebugInfoEntry[] partialFrags = new DebugInfoEntry[fragments.length - aoIndex - 1];
				System.arraycopy(fragments, aoIndex + 1, partialFrags, 0, partialFrags.length);
				return new DIEAggregate(partialFrags);
			}
		}
		throw new IllegalArgumentException("Should not get here");
	}

	/**
	 * Returns the signed integer value of the requested attribute after resolving
	 * any DWARF expression opcodes.
	 * 
	 * @param attrId {@link DWARFAttributeId} id
	 * @param defaultValue value to return if attribute is not present
	 * @return int value, or the defaultValue if attribute is not present
	 * @throws IOException if error reading value or invalid value type
	 * @throws DWARFExpressionException if error evaluating a DWARF expression
	 */
	public int parseInt(DWARFAttributeId attrId, int defaultValue)
			throws IOException, DWARFExpressionException {
		DWARFAttributeValue attr = findValue(attrId);
		if (attr == null) {
			return defaultValue;
		}

		if (attr instanceof DWARFNumericAttribute dnum) {
			return assertValidInt(dnum.getValue());
		}
		else if (attr instanceof DWARFBlobAttribute dblob) {
			DWARFExpressionEvaluator evaluator = new DWARFExpressionEvaluator(getCompilationUnit());
			evaluator.evaluate(dblob.getBytes(), 0);
			return assertValidInt(evaluator.popLong());
		}
		else {
			throw new IOException("Not integer attribute: %s".formatted(attr));
		}
	}

	/**
	 * Returns the unsigned integer value of the requested attribute after resolving
	 * any DWARF expression opcodes.
	 * 
	 * @param attrId {@link DWARFAttributeId} id
	 * @param defaultValue value to return if attribute is not present
	 * @return unsigned long value, or the defaultValue if attribute is not present
	 * @throws IOException if error reading value or invalid value type
	 * @throws DWARFExpressionException if error evaluating a DWARF expression
	 */
	public long parseUnsignedLong(DWARFAttributeId attrId, long defaultValue)
			throws IOException, DWARFExpressionException {
		DWARFAttribute attr = findAttribute(attrId);
		if (attr == null) {
			return defaultValue;
		}

		return switch (attr.getValue()) {
			case DWARFNumericAttribute dnum -> dnum.getUnsignedValue();
			case DWARFBlobAttribute dblob -> {
				DWARFExpressionEvaluator evaluator =
					new DWARFExpressionEvaluator(attr.getDIE().getCompilationUnit());
				evaluator.evaluate(dblob.getBytes(), 0);
				yield evaluator.popLong();
			}
			default -> throw new IOException("Not integer attribute: %s".formatted(attr));
		};
	}

	private int assertValidInt(long l) throws DWARFException {
		if (l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
			throw new DWARFException("Value out of allowed range: " + l);
		}
		return (int) l;
	}

	private int assertValidUInt(long l) throws DWARFException {
		if (l < 0 || l > Integer.MAX_VALUE) {
			throw new DWARFException("Value out of allowed range: " + l);
		}
		return (int) l;
	}

	/**
	 * Returns the unsigned integer value of the requested attribute after resolving
	 * any DWARF expression opcodes.
	 *
	 * @param attrId {@link DWARFAttributeId} id
	 * @param defaultValue value to return if attribute is not present
	 * @return unsigned int value, or the defaultValue if attribute is not present
	 * @throws IOException if error reading value or invalid value type
	 * @throws DWARFExpressionException if error evaluating a DWARF expression
	 */
	public int parseDataMemberOffset(DWARFAttributeId attrId, int defaultValue)
			throws DWARFExpressionException, IOException {

		DWARFAttribute attr = findAttribute(attrId);
		if (attr == null) {
			return defaultValue;
		}

		return switch (attr.getValue()) {
			case DWARFNumericAttribute dnum -> dnum.getUnsignedIntExact();
			case DWARFBlobAttribute dblob -> {
				DWARFExpressionEvaluator evaluator =
					new DWARFExpressionEvaluator(getCompilationUnit());

				// DW_AT_data_member_location expects the address of the containing object
				// to be on the stack before evaluation starts.  We don't have that so we
				// fake it with zero.
				evaluator.evaluate(dblob.getBytes(), 0);
				yield assertValidUInt(evaluator.popLong());
			}
			default -> throw new DWARFException(
				"DWARF attribute form not valid for data member offset: %s"
						.formatted(attr.getAttributeForm()));
		};
	}

	/**
	 * Parses a location attribute value, which can be a single expression that is valid for any
	 * PC, or a list of expressions that are tied to specific ranges.
	 *  
	 * @param attrId typically {@link DWARFAttributeId#DW_AT_location}
	 * @return a {@link DWARFLocationList}, never null, possibly empty
	 * @throws IOException if error reading data
	 */
	public DWARFLocationList getLocationList(DWARFAttributeId attrId) throws IOException {
		return getProgram().getLocationList(this, attrId);
	}

	/**
	 * Parses a location attribute value, and returns the {@link DWARFLocation} instance that
	 * covers the specified pc.
	 *  
	 * @param attrId typically {@link DWARFAttributeId#DW_AT_location}
	 * @param pc program counter
	 * @return a {@link DWARFLocationList}, never null, possibly empty
	 * @throws IOException if error reading data
	 */
	public DWARFLocation getLocation(DWARFAttributeId attrId, long pc) throws IOException {
		DWARFLocationList locList = getLocationList(attrId);
		return locList.getLocationContaining(pc);
	}

	/**
	 * Returns true if this DIE has a DW_AT_declaration attribute and
	 * does NOT have a matching inbound DW_AT_specification reference.
	 * 
	 * @return boolean true if this DIE has a DW_AT_declaration attribute and
	 * does NOT have a matching inbound DW_AT_specification reference
	 */
	public boolean isDanglingDeclaration() {
		return isPartialDeclaration() && fragments.length == 1;
	}

	/**
	 * Returns true if this DIE has a DW_AT_declaration attribute.
	 * @return true if this DIE has a DW_AT_declaration attribute
	 */
	public boolean isPartialDeclaration() {
		return hasAttribute(DW_AT_declaration);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("DIEAgregrate of: ");
		for (DebugInfoEntry die : fragments) {
			sb.append("DIE [0x%x], ".formatted(die.getOffset()));
		}
		sb.append("\n");
		for (DebugInfoEntry die : fragments) {
			sb.append(die.toString());
		}
		return sb.toString();
	}

	/**
	 * Parses a range list.
	 * 
	 * @param attrId attribute eg {@link DWARFAttributeId#DW_AT_ranges}
	 * @return list of ranges, or null if attribute is not present
	 * @throws IOException if an I/O error occurs
	 */
	public DWARFRangeList getRangeList(DWARFAttributeId attrId) throws IOException {
		return getProgram().getRangeList(this, attrId);
	}

	/**
	 * Return the range specified by the low_pc...high_pc attribute values.
	 * 
	 * @return {@link DWARFRange} containing low_pc - high_pc, or empty range if the low_pc is 
	 * not present
	 */
	public DWARFRange getPCRange() {
		DWARFAttribute lowPc = findAttribute(DW_AT_low_pc);
		if (lowPc != null && lowPc.getValue() instanceof DWARFNumericAttribute lowPcAttrVal) {
			try {
				// TODO: previous code excluded lowPc values that were == 0 as invalid.
				long rawLowPc = lowPcAttrVal.getUnsignedValue();
				long lowPcOffset = getProgram().getAddress(lowPc.getAttributeForm(), rawLowPc,
					getCompilationUnit());
				long highPcOffset = lowPcOffset;

				DWARFAttribute highPc = findAttribute(DW_AT_high_pc);
				if (highPc != null &&
					highPc.getValue() instanceof DWARFNumericAttribute highPcAttrVal) {
					if (highPc.getAttributeForm() == DWARFForm.DW_FORM_addr) {
						highPcOffset = highPcAttrVal.getUnsignedValue();
					}
					else {
						highPcOffset = highPcAttrVal.getUnsignedValue();
						highPcOffset = lowPcOffset + highPcOffset;
					}
				}
				return new DWARFRange(lowPcOffset, highPcOffset);
			}
			catch (IOException e) {
				// fall thru, return empty
			}
		}
		return DWARFRange.EMPTY;
	}

	/**
	 * Returns a function's parameter list, taking care to ensure that the params
	 * are well ordered (to avoid issues with concrete instance param ordering)
	 *  
	 * @return list of params for this function
	 */
	public List<DIEAggregate> getFunctionParamList() {

		// build list of params, as seen by the function's DIEA
		List<DIEAggregate> params = new ArrayList<>();
		for (DebugInfoEntry paramDIE : getChildren(DW_TAG_formal_parameter)) {
			DIEAggregate paramDIEA = getProgram().getAggregate(paramDIE);
			params.add(paramDIEA);
		}

		// since the function might be defined using an abstract and concrete parts,
		// and the param ordering of the concrete part can be inconsistent, re-order the
		// params according to the abstract instance's params.
		// Extra concrete params will be discarded.
		DIEAggregate abstractDIEA = getAbstractInstance();
		if (abstractDIEA != null) {
			List<DIEAggregate> newParams = new ArrayList<>();
			for (DebugInfoEntry paramDIE : abstractDIEA.getChildren(DW_TAG_formal_parameter)) {
				int index = findDIEInList(params, paramDIE);
				if (index >= 0) {
					newParams.add(params.get(index));
					params.remove(index);
				}
				else {
					// add generic (abstract) definition of the param to the list
					newParams.add(getProgram().getAggregate(paramDIE));
				}
			}
			if (!params.isEmpty()) {
				//Msg.warn(this, "Extra params in concrete DIE instance: " + params);
				//Msg.warn(this, this.toString());
				newParams.addAll(params);
			}
			params = newParams;
		}

		return params;
	}

	private static int findDIEInList(List<DIEAggregate> dieas, DebugInfoEntry die) {
		for (int i = 0; i < dieas.size(); i++) {
			if (dieas.get(i).hasOffset(die.getOffset())) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(fragments);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof DIEAggregate)) {
			return false;
		}
		DIEAggregate other = (DIEAggregate) obj;
		if (!Arrays.equals(fragments, other.fragments)) {
			return false;
		}
		return true;
	}

}
