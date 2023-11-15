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
package ghidra.program.model.lang.protorules;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map.Entry;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Consume multiple registers to pass a data-type
 * 
 * Available registers are consumed until the data-type is covered, and an appropriate
 * join space address is assigned.  Registers can be consumed from a specific resource list.
 * Consumption can spill over onto the stack if desired.
 */
public class MultiSlotAssign extends AssignAction {
	private StorageClass resourceType;	// Resource list from which to consume
	private boolean consumeFromStack;	// True if resources should be consumed from the stack
	private boolean consumeMostSig;		// True if resources are consumed starting with most significant bytes
	private boolean enforceAlignment;	// True if register resources are discarded to match alignment
	private boolean justifyRight;		// True if initial bytes are padding for odd data-type sizes
	private ParamEntry stackEntry;		// The stack resource
	private int firstIter;				// Iterator to first element in the resource list

	/**
	 * Cache specific ParamEntry needed by the action
	 * 
	 * Find the first ParamEntry matching the resourceType, and the ParamEntry
	 * corresponding to the stack if consumeFromStack is set.
	 * @throws InvalidInputException if the required elements are not available in the resource list
	 */
	private void initializeEntries() throws InvalidInputException {
		firstIter = -1;
		for (int i = 0; i < resource.getNumParamEntry(); ++i) {
			ParamEntry entry = resource.getEntry(i);
			if (firstIter == -1 && entry.isExclusion() && entry.getType() == resourceType &&
				entry.getAllGroups().length == 1) {
				firstIter = i;	// First matching resource size
			}
			if (!entry.isExclusion() && entry.getSpace().isStackSpace()) {
				stackEntry = entry;
				break;
			}
		}
		if (firstIter == -1) {
			throw new InvalidInputException("Could not find matching resources for action: join");
		}
		if (consumeFromStack && stackEntry == null) {
			throw new InvalidInputException("Cannot find matching <pentry> for action: join");
		}
	}

	/**
	 * Constructor for use with restoreXml
	 * @param res is the new resource set to associate with this action
	 */
	protected MultiSlotAssign(ParamListStandard res) {
		super(res);
		resourceType = StorageClass.GENERAL;	// Join general purpose registers
		consumeFromStack = !(res instanceof ParamListStandardOut);	// Spill into stack by default
		consumeMostSig = false;
		enforceAlignment = false;
		justifyRight = false;
		if (res.getEntry(0).isBigEndian()) {
			consumeMostSig = true;
			justifyRight = true;
		}
		stackEntry = null;
	}

	public MultiSlotAssign(StorageClass store, boolean stack, boolean mostSig, boolean align,
			boolean justRight, ParamListStandard res) throws InvalidInputException {
		super(res);
		resourceType = store;
		consumeFromStack = stack;
		consumeMostSig = mostSig;
		enforceAlignment = align;
		justifyRight = justRight;
		stackEntry = null;
		initializeEntries();
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new MultiSlotAssign(resourceType, consumeFromStack, consumeMostSig, enforceAlignment,
			justifyRight, newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		MultiSlotAssign otherAction = (MultiSlotAssign) op;
		if (consumeFromStack != otherAction.consumeFromStack ||
			consumeMostSig != otherAction.consumeMostSig ||
			enforceAlignment != otherAction.enforceAlignment) {
			return false;
		}
		if (firstIter != otherAction.firstIter || justifyRight != otherAction.justifyRight) {
			return false;
		}
		if (resourceType != otherAction.resourceType) {
			return false;
		}
		if (stackEntry == null && otherAction.stackEntry == null) {
			// Nothing to compare
		}
		else if (stackEntry != null && otherAction.stackEntry != null) {
			if (!stackEntry.isEquivalent(otherAction.stackEntry)) {
				return false;
			}
		}
		else {
			return false;
		}
		return true;
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		int[] tmpStatus = status.clone();
		ArrayList<Varnode> pieces = new ArrayList<>();
		ParameterPieces param = new ParameterPieces();
		int sizeLeft = dt.getLength();
		int iter = firstIter;
		int endIter = resource.getNumParamEntry();
		if (enforceAlignment) {
			int resourcesConsumed = 0;
			while (iter != endIter) {
				ParamEntry entry = resource.getEntry(iter);
				if (!entry.isExclusion()) {
					break;
				}		// Reached end of resource list
				if (entry.getType() == resourceType && entry.getAllGroups().length == 1) {	// Single register
					if (tmpStatus[entry.getGroup()] == 0) {		// Not consumed
						int align = dt.getAlignment();
						int regSize = entry.getSize();
						if (align <= regSize || (resourcesConsumed % align) == 0) {
							break;
						}
						tmpStatus[entry.getGroup()] = -1;	// Consume unaligned register
					}
					resourcesConsumed += entry.getSize();
				}
				++iter;
			}
		}
		while (sizeLeft > 0 && iter != endIter) {
			ParamEntry entry = resource.getEntry(iter);
			++iter;
			if (!entry.isExclusion()) {
				break;
			}		// Reached end of resource list
			if (entry.getType() != resourceType || entry.getAllGroups().length != 1) {
				continue;
			}		// Not a single register from desired resource list
			if (tmpStatus[entry.getGroup()] != 0) {
				continue;
			}		// Already consumed
			int trialSize = entry.getSize();
			entry.getAddrBySlot(tmpStatus[entry.getGroup()], trialSize, 1, param);
			tmpStatus[entry.getGroup()] = -1;	// Consume the register
			Varnode vn = new Varnode(param.address, trialSize);
			pieces.add(vn);
			sizeLeft -= trialSize;
		}
		boolean onePieceJoin = false;
		if (sizeLeft > 0) {				// Have to use stack to get enough bytes
			if (!consumeFromStack) {
				return FAIL;
			}
			int grp = stackEntry.getGroup();
			tmpStatus[grp] = stackEntry.getAddrBySlot(tmpStatus[grp], sizeLeft, 1, param);	// Consume all the space we need		
			Varnode vn = new Varnode(param.address, sizeLeft);
			pieces.add(vn);
		}
		else if (sizeLeft < 0) {			// Have odd data-type size
			if (resourceType == StorageClass.FLOAT && pieces.size() == 1) {
				// Floating-point register holding extended lower precision value
				onePieceJoin = true;		// Treat as "join" of full size register
			}
			else if (justifyRight) {
				// Initial bytes are padding
				Varnode vn = pieces.get(0);
				Address addr = vn.getAddress().add(-sizeLeft);
				int sz = vn.getSize() + sizeLeft;
				vn = new Varnode(addr, sz);
				pieces.set(0, vn);
			}
			else {
				int end = pieces.size() - 1;
				Varnode vn = pieces.get(end);
				int sz = vn.getSize() + sizeLeft;
				vn = new Varnode(vn.getAddress(), sz);
				pieces.set(end, vn);
			}
		}
		System.arraycopy(tmpStatus, 0, status, 0, tmpStatus.length);	// Commit resource usage for all the pieces
		res.type = dt;
		if (pieces.size() == 1 && !onePieceJoin) {
			res.address = pieces.get(0).getAddress();
			return SUCCESS;
		}
		res.joinPieces = new Varnode[pieces.size()];
		if (!consumeMostSig) {
			for (int i = 0; i < res.joinPieces.length; ++i) {
				res.joinPieces[i] = pieces.get(pieces.size() - 1 - i);
			}
		}
		else {
			for (int i = 0; i < pieces.size(); ++i) {
				res.joinPieces[i] = pieces.get(i);
			}
		}
		res.address = Address.NO_ADDRESS;		// Placeholder for join space address
		return SUCCESS;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_JOIN);
		if (resource.getEntry(0).isBigEndian() != justifyRight) {
			encoder.writeBool(ATTRIB_REVERSEJUSTIFY, true);
		}
		if (resourceType != StorageClass.GENERAL) {
			encoder.writeString(ATTRIB_STORAGE, resourceType.toString());
		}
		encoder.writeBool(ATTRIB_ALIGN, enforceAlignment);
		encoder.closeElement(ELEM_JOIN);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_JOIN.name());
		Iterator<Entry<String, String>> iter = elem.getAttributes().entrySet().iterator();
		while (iter.hasNext()) {
			Entry<String, String> attrib = iter.next();
			String name = attrib.getKey();
			if (name.equals(ATTRIB_REVERSEJUSTIFY.name())) {
				if (SpecXmlUtils.decodeBoolean(attrib.getValue())) {
					justifyRight = !justifyRight;
				}
			}
			else if (name.equals(ATTRIB_STORAGE.name())) {
				resourceType = StorageClass.getClass(attrib.getValue());
			}
			else if (name.equals(ATTRIB_ALIGN.name())) {
				enforceAlignment = SpecXmlUtils.decodeBoolean(attrib.getValue());
			}
		}
		parser.end(elem);
		try {
			initializeEntries();
		}
		catch (InvalidInputException e) {
			throw new XmlParseException(e.getMessage());
		}			// Need new firstIter
	}

}
