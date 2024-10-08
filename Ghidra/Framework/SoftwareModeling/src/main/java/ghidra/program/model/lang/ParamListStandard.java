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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Standard analysis for parameter lists
 *
 */
public class ParamListStandard implements ParamList {

	protected int numgroup;			// Number of "groups" in this parameter convention
//	protected int maxdelay;
	protected boolean thisbeforeret;	// Do hidden return pointers usurp the storage of the this pointer
	protected boolean splitMetatype;	// Are metatyped entries in separate resource sections
//	protected int[] resourceStart;		// The starting group for each resource section
	protected ParamEntry[] entry;
	protected ModelRule[] modelRules;	// Rules to apply when assigning addresses
	protected AddressSpace spacebase;	// Space containing relative offset parameters

	/**
	 * Find the (first) entry containing range
	 * @param loc  is base address of the range
	 * @param size is the size of the range in bytes
	 * @return the index of entry or -1 if we didn't find container
	 */
	private int findEntry(Address loc, int size) {
		for (int i = 0; i < entry.length; ++i) {
			if (entry[i].getMinSize() > size) {
				continue;
			}
			if (entry[i].justifiedContain(loc, size) == 0) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Assign storage for given parameter class, using the fallback assignment algorithm
	 * 
	 * Given a resource list, a data-type, and the status of previously allocated slots,
	 * select the storage location for the parameter.  The status array is
	 * indexed by group: a positive value indicates how many slots have been allocated
	 * from that group, and a -1 indicates the group/resource is fully consumed.
	 * If an Address can be assigned to the parameter, it and other details are passed back in the
	 * ParameterPieces object and the SUCCESS code is returned.  Otherwise, the FAIL code is returned.
	 * @param resource  is the resource list to allocate from
	 * @param tp is the data-type of the parameter
	 * @param matchExact is false if TYPECLASS_GENERAL is considered a match for any storage class
	 * @param status is an array marking how many slots have already been consumed in a group
	 * @param param will hold the address and other details of the assigned parameter
	 * @return either SUCCESS or FAIL
	 */
	public int assignAddressFallback(StorageClass resource, DataType tp, boolean matchExact,
			int[] status, ParameterPieces param) {
		for (ParamEntry element : entry) {
			int grp = element.getGroup();
			if (status[grp] < 0) {
				continue;
			}
			if (resource != element.getType()) {
				if (matchExact || element.getType() != StorageClass.GENERAL) {
					continue;
				}
			}

			status[grp] =
				element.getAddrBySlot(status[grp], tp.getAlignedLength(), tp.getAlignment(), param);
			if (param.address == null) {
				continue;	// -tp- does not fit in this entry
			}
			if (element.isExclusion()) {
				for (int group : element.getAllGroups()) {
					// For an exclusion entry
					status[group] = -1;			// some number of groups are taken up
				}
			}
			param.type = tp;
			return AssignAction.SUCCESS;
		}
		param.address = null;
		return AssignAction.FAIL;
	}

	/**
	 * Fill in the Address and other details for the given parameter
	 * 
	 * Attempt to apply a ModelRule first. If these do not succeed, use the fallback assignment algorithm.
	 * @param dt is the data-type assigned to the parameter
	 * @param proto is the description of the function prototype
	 * @param pos is the position of the parameter to assign (pos=-1 for output, pos >=0 for input)
	 * @param dtManager is the data-type manager for (possibly) transforming the parameter's data-type
	 * @param status is the consumed resource status array
	 * @param res is parameter description to be filled in
	 * @return the response code
	 */
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res)

	{
		if (dt.isZeroLength()) {
			return AssignAction.NO_ASSIGNMENT;
		}
		for (ModelRule modelRule : modelRules) {
			int responseCode = modelRule.assignAddress(dt, proto, pos, dtManager, status, res);
			if (responseCode != AssignAction.FAIL) {
				return responseCode;
			}
		}
		StorageClass store = ParamEntry.getBasicTypeClass(dt);
		return assignAddressFallback(store, dt, false, status, res);
	}

	/**
	 * @return the number of ParamEntry objets in this list
	 */
	public int getNumParamEntry() {
		return entry.length;
	}

	/**
	 * Within this list, get the ParamEntry at the given index
	 * @param index is the given index
	 * @return the selected ParamEntry
	 */
	public ParamEntry getEntry(int index) {
		return entry[index];
	}

	@Override
	public void assignMap(PrototypePieces proto, DataTypeManager dtManager,
			ArrayList<ParameterPieces> res, boolean addAutoParams) {
		int[] status = new int[numgroup];
		for (int i = 0; i < numgroup; ++i) {
			status[i] = 0;
		}

		boolean hiddenParam = (addAutoParams && res.size() == 2);
		
		if (hiddenParam && proto.model.isRightToLeft()) {	// Check for hidden parameters defined by the output list
			ParameterPieces last = res.get(1);
			StorageClass store;
			if (last.hiddenReturnPtr) {
				store = StorageClass.HIDDENRET;
			}
			else {
				store = ParamEntry.getBasicTypeClass(last.type);
			}
			assignAddressFallback(store, last.type, false, status, last);
			last.hiddenReturnPtr = true;
		}
		for (int i = 0; i < proto.intypes.size(); ++i) {
			ParameterPieces store = new ParameterPieces();
			res.add(store);
			int resCode = assignAddress(proto.intypes.get(i), proto, i, dtManager, status, store);
			if (resCode == AssignAction.FAIL || resCode == AssignAction.NO_ASSIGNMENT) {
				// Do not continue to assign after first failure
				++i;
				while (i < proto.intypes.size()) {
					store = new ParameterPieces();		// Fill out with UNASSIGNED pieces
					res.add(store);
					++i;
				}
				return;
			}
		}
		if (hiddenParam && !proto.model.isRightToLeft()) {	// Check for hidden parameters defined by the output list
			ParameterPieces last = res.get(1);
			StorageClass store;
			if (last.hiddenReturnPtr) {
				store = StorageClass.HIDDENRET;
			}
			else {
				store = ParamEntry.getBasicTypeClass(last.type);
			}
			assignAddressFallback(store, last.type, false, status, last);
			last.hiddenReturnPtr = true;
		}
	}

	@Override
	public VariableStorage[] getPotentialRegisterStorage(Program prog) {
		ArrayList<VariableStorage> res = new ArrayList<>();
		for (ParamEntry element : entry) {
			ParamEntry pe = element;
			if (!pe.isExclusion()) {
				continue;
			}
			if (pe.getSpace().isRegisterSpace()) {
				VariableStorage var = null;
				try {
					var = new VariableStorage(prog, pe.getSpace().getAddress(pe.getAddressBase()),
						pe.getSize());
				}
				catch (InvalidInputException e) {
					// Skip this particular storage location
				}
				if (var != null) {
					res.add(var);
				}
			}
		}
		VariableStorage[] arres = new VariableStorage[res.size()];
		res.toArray(arres);
		return arres;
	}

	@Override
	public void encode(Encoder encoder, boolean isInput) throws IOException {
		encoder.openElement(isInput ? ELEM_INPUT : ELEM_OUTPUT);
		if (thisbeforeret) {
			encoder.writeBool(ATTRIB_THISBEFORERETPOINTER, true);
		}
		if (isInput && !splitMetatype) {
			encoder.writeBool(ATTRIB_SEPARATEFLOAT, false);
		}
		int curgroup = -1;
		for (ParamEntry el : entry) {
			if (curgroup >= 0) {
				if (!el.isGrouped() || el.getGroup() != curgroup) {
					encoder.closeElement(ELEM_GROUP);
					curgroup = -1;
				}
			}
			if (el.isGrouped()) {
				if (curgroup < 0) {
					encoder.openElement(ELEM_GROUP);
					curgroup = el.getGroup();
				}
			}
			el.encode(encoder);
		}
		if (curgroup >= 0) {
			encoder.closeElement(ELEM_GROUP);
		}
		for (ModelRule modelRule : modelRules) {
			modelRule.encode(encoder);
		}
		encoder.closeElement(isInput ? ELEM_INPUT : ELEM_OUTPUT);
	}

	private void parsePentry(XmlPullParser parser, CompilerSpec cspec, ArrayList<ParamEntry> pe,
			int groupid, boolean splitFloat, boolean grouped) throws XmlParseException {
		StorageClass lastClass = StorageClass.CLASS4;
		if (!pe.isEmpty()) {
			ParamEntry lastEntry = pe.get(pe.size() - 1);
			lastClass = lastEntry.isGrouped() ? StorageClass.GENERAL : lastEntry.getType();
		}
		ParamEntry pentry = new ParamEntry(groupid);
		pe.add(pentry);
		pentry.restoreXml(parser, cspec, pe, grouped);
		if (splitFloat) {
			StorageClass currentClass = grouped ? StorageClass.GENERAL : pentry.getType();
			if (lastClass != currentClass) {
				if (lastClass.getValue() < currentClass.getValue()) {
					throw new XmlParseException(
						"parameter list entries must be ordered by storage class");
				}
//				int[] newResourceStart = new int[resourceStart.length + 1];
//				System.arraycopy(resourceStart, 0, newResourceStart, 0, resourceStart.length);
//				newResourceStart[resourceStart.length] = groupid;
//				resourceStart = newResourceStart;
			}
		}
		if (pentry.getSpace().isStackSpace()) {
			spacebase = pentry.getSpace();
		}
		int[] groupSet = pentry.getAllGroups();
		int maxgroup = groupSet[groupSet.length - 1] + 1;
		if (maxgroup > numgroup) {
			numgroup = maxgroup;
		}
	}

	private void parseGroup(XmlPullParser parser, CompilerSpec cspec, ArrayList<ParamEntry> pe,
			int groupid, boolean splitFloat) throws XmlParseException {
		XmlElement el = parser.start("group");
		int basegroup = numgroup;
		int count = 0;
		while (parser.peek().isStart()) {
			parsePentry(parser, cspec, pe, basegroup, splitFloat, true);
			count += 1;
			ParamEntry lastEntry = pe.get(pe.size() - 1);
			if (lastEntry.getSpace().getType() == AddressSpace.TYPE_JOIN) {
				throw new XmlParseException(
					"<pentry> in the join space not allowed in <group> tag");
			}
		}
		// Check that all entries in the group are distinguishable
		for (int i = 1; i < count; ++i) {
			ParamEntry curEntry = pe.get(pe.size() - 1 - i);
			for (int j = 0; j < i; ++j) {
				ParamEntry.orderWithinGroup(curEntry, pe.get(pe.size() - 1 - j));
			}
		}
		parser.end(el);
	}

	@Override
	public void restoreXml(XmlPullParser parser, CompilerSpec cspec) throws XmlParseException {
		ArrayList<ParamEntry> pe = new ArrayList<>();
		numgroup = 0;
		spacebase = null;
		int pointermax = 0;
		thisbeforeret = false;
		splitMetatype = true;
		XmlElement mainel = parser.start();
		String attribute = mainel.getAttribute("pointermax");
		if (attribute != null) {
			pointermax = SpecXmlUtils.decodeInt(attribute);
		}
		attribute = mainel.getAttribute("thisbeforeretpointer");
		if (attribute != null) {
			thisbeforeret = SpecXmlUtils.decodeBoolean(attribute);
		}
		attribute = mainel.getAttribute("separatefloat");
		if (attribute != null) {
			splitMetatype = SpecXmlUtils.decodeBoolean(attribute);
		}
//		resourceStart = new int[0];
		for (;;) {
			XmlElement el = parser.peek();
			if (!el.isStart()) {
				break;
			}
			if (el.getName().equals("pentry")) {
				parsePentry(parser, cspec, pe, numgroup, splitMetatype, false);
			}
			else if (el.getName().equals("group")) {
				parseGroup(parser, cspec, pe, numgroup, splitMetatype);
			}
			else if (el.getName().equals("rule")) {
				break;
			}
		}
		entry = new ParamEntry[pe.size()];
		pe.toArray(entry);

		ArrayList<ModelRule> rules = new ArrayList<>();
		for (;;) {
			XmlElement subId = parser.peek();
			if (!subId.isStart()) {
				break;
			}
			if (subId.getName().equals("rule")) {
				ModelRule rule = new ModelRule();
				rule.restoreXml(parser, this);
				rules.add(rule);
			}
			else {
				throw new XmlParseException(
					"<pentry> and <group> elements must come before any <modelrule>");
			}
		}

		parser.end(mainel);
//		int[] newResourceStart = new int[resourceStart.length + 1];
//		System.arraycopy(resourceStart, 0, newResourceStart, 0, resourceStart.length);
//		newResourceStart[resourceStart.length] = numgroup;
//		resourceStart = newResourceStart;
		if (pointermax > 0) {	// Add a ModelRule at the end that converts too big data-types to pointers
			SizeRestrictedFilter typeFilter = new SizeRestrictedFilter(pointermax + 1, 0);
			ConvertToPointer action = new ConvertToPointer(this);
			try {
				rules.add(new ModelRule(typeFilter, action, this));
			}
			catch (InvalidInputException e) {
				throw new XmlParseException(e.getMessage());
			}
		}
		modelRules = new ModelRule[rules.size()];
		rules.toArray(modelRules);
	}

	@Override
	public int getStackParameterAlignment() {
		for (ParamEntry pentry : entry) {
			if (pentry.getSpace().isStackSpace()) {
				return pentry.getAlign();
			}
		}
		return -1;
	}

	@Override
	public Long getStackParameterOffset() {
		for (ParamEntry element : entry) {
			ParamEntry pentry = element;
			if (pentry.isExclusion()) {
				continue;
			}
			if (!pentry.getSpace().isStackSpace()) {
				continue;
			}
			long res = pentry.getAddressBase();
			if (pentry.isReverseStack()) {
				res += pentry.getSize();
			}
			res = pentry.getSpace().truncateOffset(res);
			return res;
		}
		return null;
	}

	@Override
	public boolean possibleParamWithSlot(Address loc, int size, WithSlotRec res) {
		if (loc == null) {
			return false;
		}
		int num = findEntry(loc, size);
		if (num == -1) {
			return false;
		}
		ParamEntry curentry = entry[num];
		res.slot = curentry.getSlot(loc, 0);
		if (curentry.isExclusion()) {
			res.slotsize = curentry.getAllGroups().length;
		}
		else {
			res.slotsize = ((size - 1) / curentry.getAlign()) + 1;
		}
		return true;
	}

	@Override
	public AddressSpace getSpacebase() {
		return spacebase;
	}

	@Override
	public boolean isEquivalent(ParamList obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		ParamListStandard op2 = (ParamListStandard) obj;
		if (entry.length != op2.entry.length) {
			return false;
		}
		for (int i = 0; i < entry.length; ++i) {
			if (!entry[i].isEquivalent(op2.entry[i])) {
				return false;
			}
		}
		if (modelRules.length != op2.modelRules.length) {
			return false;
		}
		for (int i = 0; i < modelRules.length; ++i) {
			if (!modelRules[i].isEquivalent(op2.modelRules[i])) {
				return false;
			}
		}
		if (numgroup != op2.numgroup) {
			return false;
		}
		if (!SystemUtilities.isEqual(spacebase, op2.spacebase)) {
			return false;
		}
		if (thisbeforeret != op2.thisbeforeret) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isThisBeforeRetPointer() {
		return thisbeforeret;
	}
}
