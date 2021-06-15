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

import java.io.IOException;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.attribs.*;
import ghidra.app.util.bin.format.dwarf4.encoding.*;
import ghidra.app.util.bin.format.dwarf4.expression.*;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.util.Msg;
import ghidra.util.NumberUtil;

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
	 * <p>
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
		while ((tmp = result.getRefDIE(DWARFAttribute.DW_AT_abstract_origin)) != null &&
			!result.hasOffset(tmp.getOffset()) && result.getFragmentCount() < MAX_FRAGMENT_COUNT) {
			result.addFragment(tmp);
		}

		// look for 1 spec DIE and add it.
		tmp = result.getRefDIE(DWARFAttribute.DW_AT_specification);
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
	 * @param source
	 * @return
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
	 * <p>
	 * @param die
	 * @return
	 */
	public static DIEAggregate createSingle(DebugInfoEntry die) {
		DIEAggregate result = new DIEAggregate(new DebugInfoEntry[] { die });

		return result;
	}

	/**
	 * Private ctor to force use of the static factory methods {@link #createFromHead(DebugInfoEntry)}
	 * and {@link #createSingle(DebugInfoEntry)}.
	 * @param die
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
	 * @param newDIE
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
	 * @return
	 */
	public String getHexOffset() {
		return Long.toHexString(getHeadFragment().getOffset());
	}

	public int getTag() {
		return getHeadFragment().getTag();
	}

	public DWARFCompilationUnit getCompilationUnit() {
		return getHeadFragment().getCompilationUnit();
	}

	public DWARFProgram getProgram() {
		return getHeadFragment().getCompilationUnit().getProgram();
	}

	/**
	 * Returns the last {@link DebugInfoEntry DIE} fragment, ie. the decl DIE.
	 * @return
	 */
	public DebugInfoEntry getLastFragment() {
		return fragments[fragments.length - 1];
	}

	/**
	 * Returns the first {@link DebugInfoEntry DIE} fragment, ie. the spec or abstract_origin
	 * DIE.
	 * @return
	 */
	public DebugInfoEntry getHeadFragment() {
		return fragments[0];
	}

	public DIEAggregate getDeclParent() {
		DebugInfoEntry declDIE = getLastFragment();
		DebugInfoEntry declParent = declDIE.getParent();
		return getCompilationUnit().getProgram().getAggregate(declParent);
	}

	public DIEAggregate getParent() {
		DebugInfoEntry die = getHeadFragment();
		DebugInfoEntry parent = die.getParent();
		return getCompilationUnit().getProgram().getAggregate(parent);
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
	 * @return
	 */
	public int getDepth() {
		DebugInfoEntry die = getHeadFragment();
		int result = 0;
		while (die != null) {
			result++;
			die = die.getParent();
		}
		return result - 1;
	}

	private AttrInfo findAttribute(int attribute) {
		for (DebugInfoEntry die : fragments) {
			DWARFAttributeValue[] dieAttrValues = die.getAttributes();
			DWARFAttributeSpecification[] attrDefs = die.getAbbreviation().getAttributes();
			for (int i = 0; i < attrDefs.length; i++) {
				DWARFAttributeSpecification attrDef = attrDefs[i];
				if (attrDef.getAttribute() == attribute) {
					DWARFAttributeValue attrVal = dieAttrValues[i];
					DWARFForm form = attrDef.getAttributeForm();
					if (attrVal instanceof DWARFIndirectAttribute) {
						form = ((DWARFIndirectAttribute) attrVal).getForm();
						attrVal = ((DWARFIndirectAttribute) attrVal).getValue();
					}
					return new AttrInfo(attrVal, die, form);
				}
			}
		}
		return null;
	}

	/**
	 * Finds a {@link DWARFAttributeValue attribute} with a matching {@link DWARFAttribute} type
	 * <p>
	 * Returns null if the attribute does not exist or is wrong java class type.
	 * <p>
	 * Attributes are searched for in each fragment in this aggregate, starting with the
	 * 'head' fragment, progressing toward the 'decl' fragment.
	 * <p>
	 *
	 * @param attribute See {@link DWARFAttribute}
	 * @param clazz must be derived from {@link DWARFAttributeValue}
	 * @return
	 */
	public <T extends DWARFAttributeValue> T getAttribute(int attribute, Class<T> clazz) {
		AttrInfo attrInfo = findAttribute(attribute);
		return attrInfo != null ? attrInfo.getValue(clazz) : null;
	}

	public DWARFAttributeValue getAttribute(int attribute) {
		return getAttribute(attribute, DWARFAttributeValue.class);
	}

	/**
	 * Returns the value of the requested attribute, or -defaultValue- if the
	 * attribute is missing.
	 *
	 * @param attribute
	 * @param defaultValue
	 * @return
	 */
	public long getLong(int attribute, long defaultValue) {
		DWARFNumericAttribute attr = getAttribute(attribute, DWARFNumericAttribute.class);
		return (attr != null) ? attr.getValue() : defaultValue;
	}

	/**
	 * Returns the boolean value of the requested attribute, or -defaultValue- if
	 * the attribute is missing or not the correct type.
	 * <p>
	 * @param attribute
	 * @param defaultValue
	 * @return
	 */
	public boolean getBool(int attribute, boolean defaultValue) {
		DWARFBooleanAttribute val = getAttribute(attribute, DWARFBooleanAttribute.class);
		return (val != null) ? val.getValue() : defaultValue;
	}

	/**
	 * Returns the string value of the requested attribute, or -defaultValue- if
	 * the attribute is missing or not the correct type.
	 * <p>
	 * @param attribute
	 * @param defaultValue
	 * @return
	 */
	public String getString(int attribute, String defaultValue) {
		DWARFStringAttribute attr = getAttribute(attribute, DWARFStringAttribute.class);
		return (attr != null) ? attr.getValue(getProgram().getDebugStrings()) : defaultValue;
	}

	/**
	 * Returns the string value of the {@link DWARFAttribute#DW_AT_name dw_at_name} attribute,
	 * or null if it is missing.
	 * <p>
	 * @return
	 */
	public String getName() {
		return getString(DWARFAttribute.DW_AT_name, null);
	}

	/**
	 * Returns the unsigned long integer value of the requested attribute, or -defaultValue-
	 * if the attribute is missing.
	 * <p>
	 * The 'unsigned'ness of this method refers to how the binary value is read from
	 * the dwarf information (ie. a value with the high bit set is not treated as signed).
	 * <p>
	 * The -defaultValue- parameter can accept a negative value.
	 * @param attribute
	 * @param defaultValue
	 * @return
	 */
	public long getUnsignedLong(int attribute, long defaultValue) {
		DWARFNumericAttribute attr = getAttribute(attribute, DWARFNumericAttribute.class);
		return (attr != null) ? attr.getUnsignedValue() : defaultValue;
	}

	/**
	 * Returns the {@link DebugInfoEntry die} instance pointed to by the requested attribute,
	 * or null if the attribute does not exist.
	 * <p>
	 * @param attribute
	 * @return
	 */
	public DebugInfoEntry getRefDIE(int attribute) {
		AttrInfo attrInfo = findAttribute(attribute);
		if (attrInfo == null) {
			return null;
		}

		DWARFNumericAttribute val = attrInfo.getValue(DWARFNumericAttribute.class);
		long offset = (val != null) ? val.getUnsignedValue() : -1;

		DebugInfoEntry result = getProgram().getEntryAtByteOffsetUnchecked(offset);
		if (result == null) {
			Msg.warn(this, "Invalid reference value [" + Long.toHexString(offset) + "]");
			Msg.warn(this, this.toString());
		}
		return result;
	}

	public DIEAggregate getRef(int attribute) {
		DebugInfoEntry die = getRefDIE(attribute);
		return getCompilationUnit().getProgram().getAggregate(die);
	}

	/**
	 * Returns the DIE pointed to by a DW_AT_containing_type attribute.
	 *
	 * @return DIEA pointed to by the DW_AT_containing_type attribute, or null if not present.
	 */
	public DIEAggregate getContainingTypeRef() {
		return getRef(DWARFAttribute.DW_AT_containing_type);
	}

	public DIEAggregate getTypeRef() {
		return getRef(DWARFAttribute.DW_AT_type);
	}

	public boolean hasAttribute(int attribute) {
		return findAttribute(attribute) != null;
	}

	/**
	 * Returns the signed integer value of the requested attribute after resolving
	 * any DWARF expression opcodes.
	 * <p>
	 * @param attribute
	 * @param defaultValue
	 * @return
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	public int parseInt(int attribute, int defaultValue)
			throws IOException, DWARFExpressionException {
		AttrInfo attrInfo = findAttribute(attribute);
		if (attrInfo == null) {
			return defaultValue;
		}

		DWARFAttributeValue attr = attrInfo.attr;
		if (attr instanceof DWARFNumericAttribute) {
			return assertValidInt(((DWARFNumericAttribute) attr).getValue());
		}
		else if (attr instanceof DWARFBlobAttribute) {
			byte[] exprBytes = ((DWARFBlobAttribute) attr).getBytes();
			DWARFExpressionEvaluator evaluator = DWARFExpressionEvaluator.create(getHeadFragment());
			ghidra.app.util.bin.format.dwarf4.expression.DWARFExpression expr =
				evaluator.readExpr(exprBytes);

			evaluator.evaluate(expr, 0);
			return assertValidInt(evaluator.pop());
		}
		else {
			throw new IOException(
				"DWARF attribute form not valid for integer value: " + attrInfo.form);
		}
	}

	/**
	 * Returns the unsigned integer value of the requested attribute after resolving
	 * any DWARF expression opcodes.
	 * <p>
	 * @param attribute
	 * @param defaultValue
	 * @return
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	public long parseUnsignedLong(int attribute, long defaultValue)
			throws IOException, DWARFExpressionException {
		AttrInfo attrInfo = findAttribute(attribute);
		if (attrInfo == null) {
			return defaultValue;
		}

		DWARFAttributeValue attr = attrInfo.attr;
		if (attr instanceof DWARFNumericAttribute) {
			return ((DWARFNumericAttribute) attr).getUnsignedValue();
		}
		else if (attr instanceof DWARFBlobAttribute) {
			byte[] exprBytes = ((DWARFBlobAttribute) attr).getBytes();
			DWARFExpressionEvaluator evaluator = DWARFExpressionEvaluator.create(getHeadFragment());
			DWARFExpression expr = evaluator.readExpr(exprBytes);

			evaluator.evaluate(expr, 0);
			return evaluator.pop();
		}
		else {
			throw new IOException(
				"DWARF attribute form not valid for integer value: " + attrInfo.form);
		}
	}

	private int assertValidInt(long l) throws IOException {
		if (l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
			throw new IOException("Value out of allowed range: " + l);
		}
		return (int) l;
	}

	private int assertValidUInt(long l) throws IOException {
		if (l < 0 || l > Integer.MAX_VALUE) {
			throw new IOException("Value out of allowed range: " + l);
		}
		return (int) l;
	}

	/**
	 * Returns the unsigned integer value of the requested attribute after resolving
	 * any DWARF expression opcodes.
	 *
	 * @param attribute
	 * @param defaultValue
	 * @return
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	public int parseDataMemberOffset(int attribute, int defaultValue)
			throws IOException, DWARFExpressionException {

		AttrInfo attrInfo = findAttribute(attribute);
		if (attrInfo == null) {
			return defaultValue;
		}

		DWARFAttributeValue attr = attrInfo.attr;
		if (attr instanceof DWARFNumericAttribute) {
			return assertValidUInt(((DWARFNumericAttribute) attr).getUnsignedValue());
		}
		else if (attr instanceof DWARFBlobAttribute) {
			byte[] exprBytes = ((DWARFBlobAttribute) attr).getBytes();
			DWARFExpressionEvaluator evaluator = DWARFExpressionEvaluator.create(getHeadFragment());
			ghidra.app.util.bin.format.dwarf4.expression.DWARFExpression expr =
				evaluator.readExpr(exprBytes);

			// DW_AT_data_member_location expects the address of the containing object
			// to be on the stack before evaluation starts.  We don't have that so we
			// fake it with zero.
			evaluator.evaluate(expr, 0);
			return assertValidUInt(evaluator.pop());
		}
		else {
			throw new IOException(
				"DWARF attribute form not valid for data member offset: " + attrInfo.form);
		}
	}

	/**
	 * Returns the location list info specified in the attribute.
	 * <p>
	 * Numeric attributes are treated as offsets into the debug_loc section.
	 * <p>
	 * Blob attributes are treated as a single location record for the current CU, using the
	 * blob bytes as the DWARF expression of the location record.
	 * <p>
	 * @param attribute
	 * @return
	 * @throws IOException
	 */
	public List<DWARFLocation> getAsLocation(int attribute) throws IOException {
		AttrInfo attrInfo = findAttribute(attribute);
		if (attrInfo == null) {
			return Collections.EMPTY_LIST;
		}
		else if (attrInfo.attr instanceof DWARFNumericAttribute) {
			return readDebugLocList(((DWARFNumericAttribute) attrInfo.attr).getUnsignedValue());
		}
		else if (attrInfo.attr instanceof DWARFBlobAttribute) {
			return _exprBytesAsLocation((DWARFBlobAttribute) attrInfo.attr);
		}
		else {
			throw new UnsupportedOperationException(
				"This method is unsupported for the attribute type " + attrInfo.form + ".");
		}
	}

	/**
	 * Evaluate the DWARFExpression located in the DWARFLocation object in the context of
	 * this DIEA.
	 * <p>
	 * @param location
	 * @return
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	public long evaluateLocation(DWARFLocation location)
			throws IOException, DWARFExpressionException {
		DWARFExpressionEvaluator evaluator = DWARFExpressionEvaluator.create(getHeadFragment());
		DWARFExpression expr = evaluator.readExpr(location.getLocation());

		evaluator.evaluate(expr);
		return evaluator.pop();
	}

	/**
	 * Return a list of DWARF locations read from the debug_loc section.
	 * @param offset offset into the debug_loc section
	 * @return list of DWARF locations (address range and location expression)
	 * @throws IOException if an I/O error occurs
	 */
	private List<DWARFLocation> readDebugLocList(long offset) throws IOException {
		BinaryReader debug_loc = getCompilationUnit().getProgram().getDebugLocation();

		List<DWARFLocation> ranges = new ArrayList<>();
		if (debug_loc == null) {
			return ranges;
		}

		debug_loc.setPointerIndex(offset);
		byte pointerSize = getCompilationUnit().getPointerSize();

		Number baseAddress = getCompilationUnit().getCompileUnit().getLowPC();
		long baseAddressOffset = (baseAddress != null) ? baseAddress.longValue() : 0;

		Number cuLowPC = getCompilationUnit().getCompileUnit().getLowPC();
		long cuBase = (cuLowPC != null) ? cuLowPC.longValue() : Long.MAX_VALUE;

		// Loop through the debug_loc entry
		while (debug_loc.getPointerIndex() < debug_loc.length()) {
			Number beginning = DWARFUtil.readAddress(debug_loc, pointerSize);
			Number ending = DWARFUtil.readAddress(debug_loc, pointerSize);

			// List end
			if (beginning.longValue() == 0 && ending.longValue() == 0) {
				break;
			}

			// Check to see if this is a base address entry
			if (NumberUtil.equalsMaxUnsignedValue(beginning)) {
				baseAddressOffset = ending.longValue();
				continue;
			}

			// Size is 2 bytes
			int size = debug_loc.readNextShort() & NumberUtil.UNSIGNED_SHORT_MASK;

			// Read the location description
			byte[] location = debug_loc.readNextByteArray(size);

			// Test to see if the 'offset' read from the debug_loc data is already
			// greater-than the compunit's lowpc.  This indicates the 'offset' isn't
			// an offset, but already an absolute value.  This occurs in some
			// gcc dwarf compilation flag combinations.
			boolean isBadOffset = (beginning.longValue() > cuBase);

			long absStart = beginning.longValue();
			long absEnd = ending.longValue();
			if (!isBadOffset) {
				absStart += baseAddressOffset;
				absEnd += baseAddressOffset;
			}

			// TODO: verify end addr calc with DWARFstd.pdf, inclusive vs exclusive
			ranges.add(new DWARFLocation(new DWARFRange(absStart, absEnd + 1), location));
		}
		return ranges;
	}

	private List<DWARFLocation> _exprBytesAsLocation(DWARFBlobAttribute attr) {
		List<DWARFLocation> list = new ArrayList<>(1);

		Number highPc = getCompilationUnit().getCompileUnit().getHighPC();
		Number lowPc = getCompilationUnit().getCompileUnit().getLowPC();
		if (highPc == null) {
			// a DW_AT_high_pc is not required
			// in this case presumably we don't have to choose from a location list based on range
			// Make a 1-byte range
			highPc = lowPc;
		}
		// If there is no low either, assume we don't need a range, and make a (0,0) range
		DWARFRange range = (lowPc == null) ? new DWARFRange(0, 0)
				: new DWARFRange(lowPc.longValue(), highPc.longValue());
		list.add(new DWARFLocation(range, attr.getBytes()));
		return list;
	}

	/**
	 * Returns true if this DIE has a DW_AT_declaration attribute and
	 * does NOT have a matching inbound DW_AT_specification reference.
	 * <p>
	 * @return
	 */
	public boolean isDanglingDeclaration() {
		return isPartialDeclaration() && fragments.length == 1;
	}

	/**
	 * Returns true if this DIE has a DW_AT_declaration attribute.
	 * @return
	 */
	public boolean isPartialDeclaration() {
		return hasAttribute(DWARFAttribute.DW_AT_declaration);
	}

	public boolean isNamedType() {
		switch (getTag()) {
			case DWARFTag.DW_TAG_base_type:
			case DWARFTag.DW_TAG_typedef:
			case DWARFTag.DW_TAG_namespace:
			case DWARFTag.DW_TAG_subprogram:
			case DWARFTag.DW_TAG_class_type:
			case DWARFTag.DW_TAG_interface_type:
			case DWARFTag.DW_TAG_structure_type:
			case DWARFTag.DW_TAG_union_type:
			case DWARFTag.DW_TAG_enumeration_type:
			case DWARFTag.DW_TAG_subroutine_type:
			case DWARFTag.DW_TAG_unspecified_type:
				return true;

			case DWARFTag.DW_TAG_pointer_type:
			case DWARFTag.DW_TAG_reference_type:
			case DWARFTag.DW_TAG_const_type:
			case DWARFTag.DW_TAG_lexical_block:
			default:
				return false;
		}
	}

	/**
	 * Returns true if the children of this DIE are within a new namespace.
	 * <p>
	 * Ie. Namespaces, subprogram, class, interface, struct, union, enum
	 * @return
	 */
	public boolean isNameSpaceContainer() {
		switch (getTag()) {
			case DWARFTag.DW_TAG_namespace:
			case DWARFTag.DW_TAG_subprogram:
			case DWARFTag.DW_TAG_lexical_block:
			case DWARFTag.DW_TAG_class_type:
			case DWARFTag.DW_TAG_interface_type:
			case DWARFTag.DW_TAG_structure_type:
			case DWARFTag.DW_TAG_union_type:
			case DWARFTag.DW_TAG_enumeration_type:
				return true;
		}
		return false;
	}

	/**
	 * Returns true if this DIE defines a structure-like element (class, struct, interface, union).
	 *
	 * @return
	 */
	public boolean isStructureType() {
		switch (getTag()) {
			case DWARFTag.DW_TAG_class_type:
			case DWARFTag.DW_TAG_interface_type:
			case DWARFTag.DW_TAG_structure_type:
			case DWARFTag.DW_TAG_union_type:
				return true;
		}
		return false;
	}

	public boolean isFuncDefType() {
		switch (getTag()) {
			case DWARFTag.DW_TAG_subprogram:
			case DWARFTag.DW_TAG_subroutine_type:
				return true;
		}
		return false;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("DIEAgregrate of: ");
		for (DebugInfoEntry die : fragments) {
			sb.append("DIE [").append(Long.toHexString(die.getOffset())).append("], ");
		}
		sb.append("\n");
		for (DebugInfoEntry die : fragments) {
			sb.append(die.toString());
		}
		return sb.toString();
	}

	/**
	 * Parses a range list from the debug_ranges section.
	 * See DWARF4 Section 2.17.3 (Non-Contiguous Address Ranges).
	 * <p>
	 * @param attribute attribute ie. {@link DWARFAttribute#DW_AT_ranges}
	 * @return list of ranges
	 * @throws IOException if an I/O error occurs
	 */
	public List<DWARFRange> parseDebugRange(int attribute) throws IOException {
		byte pointerSize = getCompilationUnit().getPointerSize();
		BinaryReader reader = getCompilationUnit().getProgram().getDebugRanges();

		long offset = getUnsignedLong(attribute, -1);
		if (offset == -1) {
			throw new IOException("Bad / missing attribute " + attribute);
		}
		reader.setPointerIndex(offset);
		List<DWARFRange> ranges = new ArrayList<>();

		long baseAddress = getCompilationUnit().getCompileUnit() != null &&
			getCompilationUnit().getCompileUnit().getLowPC() != null
					? getCompilationUnit().getCompileUnit().getLowPC().longValue()
					: 0L;

		while (reader.getPointerIndex() < reader.length()) {
			// Read the beginning and ending addresses
			Number beginning = DWARFUtil.readAddress(reader, pointerSize);
			Number ending = DWARFUtil.readAddress(reader, pointerSize);	// dwarf end addrs are exclusive

			// End of the list
			if (beginning.longValue() == 0 && ending.longValue() == 0) {
				break;
			}

			// Check to see if this is a base address entry
			if (NumberUtil.equalsMaxUnsignedValue(beginning)) {
				baseAddress = ending.longValue();
				continue;
			}

			// Add the range to the list
			ranges.add(new DWARFRange(baseAddress + beginning.longValue(),
				baseAddress + ending.longValue()));
		}
		Collections.sort(ranges);
		return ranges;
	}

	/**
	 * Returns the value of the DW_AT_low_pc attribute, if it exists.
	 *
	 * @param defaultValue
	 * @return
	 */
	public long getLowPC(long defaultValue) {
		DWARFNumericAttribute attr =
			getAttribute(DWARFAttribute.DW_AT_low_pc, DWARFNumericAttribute.class);
		return (attr != null) ? attr.getUnsignedValue() + getProgram().getProgramBaseAddressFixup()
				: defaultValue;
	}

	/**
	 * Returns the value of the DW_AT_high_pc attribute, adjusted
	 * if necessary by the value of DW_AT_low_pc.
	 * <p>
	 * @return
	 * @throws IOException if the DW_AT_high_pc attribute isn't a numeric
	 * attribute, or if the DW_AT_low_pc value is needed and is not present.
	 */
	public long getHighPC() throws IOException {
		AttrInfo high = findAttribute(DWARFAttribute.DW_AT_high_pc);
		if (high != null && high.attr instanceof DWARFNumericAttribute) {
			DWARFNumericAttribute highVal = (DWARFNumericAttribute) high.attr;

			// if the DWARF attr was a DW_FORM_addr, it doesn't need fixing up
			if (high.form == DWARFForm.DW_FORM_addr) {
				return highVal.getUnsignedValue() + getProgram().getProgramBaseAddressFixup() - 1;
			}

			// else it was a DW_FORM_data value and is relative to the lowPC value
			DWARFNumericAttribute low =
				getAttribute(DWARFAttribute.DW_AT_low_pc, DWARFNumericAttribute.class);
			
			long lhighVal = highVal.getUnsignedValue();
			if (lhighVal == 0) {
				lhighVal = 1;
			}
			if (low != null && lhighVal > 0) {
				return low.getUnsignedValue() + getProgram().getProgramBaseAddressFixup() +
						lhighVal - 1;
			}
		}
		throw new IOException("Bad/unsupported DW_AT_high_pc attribute value or type");
	}

	/**
	 * Returns true if the raw lowPc and highPc values are the same.
	 * <p>
	 * This indicates an empty range, in which case the caller may want to take
	 * special steps to avoid issues with Ghidra ranges.
	 * <p>
	 * Only seen in extremely old gcc versions.  Typically the low & high
	 * pc values are omitted if the CU is empty.
	 * 
	 * @return boolean true if the LowPC and HighPC values are present and equal
	 */
	public boolean isLowPCEqualHighPC() {
		AttrInfo low = findAttribute(DWARFAttribute.DW_AT_low_pc);
		AttrInfo high = findAttribute(DWARFAttribute.DW_AT_high_pc);
		if (low != null && high != null && low.form == high.form &&
			low.attr instanceof DWARFNumericAttribute &&
			high.attr instanceof DWARFNumericAttribute) {
			DWARFNumericAttribute lowVal = (DWARFNumericAttribute) low.attr;
			DWARFNumericAttribute highVal = (DWARFNumericAttribute) high.attr;
			return lowVal.getValue() == highVal.getValue();
		}
		return false;
	}

	/**
	 * A simple class used by findAttribute() to return the found attribute, along with
	 * the DIE it was found in, and the DWARFForm type of the raw attribute.
	 */
	static class AttrInfo {
		DWARFAttributeValue attr;
		DebugInfoEntry die;
		DWARFForm form;

		AttrInfo(DWARFAttributeValue attr, DebugInfoEntry die, DWARFForm form) {
			this.attr = attr;
			this.die = die;
			this.form = form;
		}

		<T extends DWARFAttributeValue> T getValue(Class<T> clazz) {
			if (attr != null && clazz.isAssignableFrom(attr.getClass())) {
				return clazz.cast(attr);
			}
			return null;
		}

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
