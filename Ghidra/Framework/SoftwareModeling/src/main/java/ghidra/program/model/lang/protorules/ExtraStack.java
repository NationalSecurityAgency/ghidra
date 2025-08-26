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
import java.util.Iterator;
import java.util.Map.Entry;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Consume stack resources as a side-effect
 * 
 * This action is a side-effect and doesn't assign an address for the current parameter.
 * If the current parameter has been assigned a address that is not on the stack, this action consumes
 * stack resources as if the parameter were allocated to the stack.  If the current parameter was
 * already assigned a stack address, no additional action is taken. 
 */
public class ExtraStack extends AssignAction {

	private ParamEntry stackEntry;	// Parameter entry corresponding to the stack
	private int afterBytes; // Activate side effect after given number of bytes consumed
	private StorageClass afterStorage; // Active side effect after given amount of this storage consumed

	/**
	 * Find stack entry in resource list
	 * @throws InvalidInputException if there is no stack entry
	 */
	private void initializeEntry() throws InvalidInputException {
		for (int i = 0; i < resource.getNumParamEntry(); ++i) {
			ParamEntry entry = resource.getEntry(i);
			if (!entry.isExclusion() && entry.getSpace().isStackSpace()) {
				stackEntry = entry;
				break;
			}
		}
		if (stackEntry == null) {
			throw new InvalidInputException(
				"Cannot find matching <pentry> for action: extra_stack");
		}
	}

	/**
	 * Constructor for use with restoreXml
	 * @param res is the resource list
	 * @param val is a dummy variable
	 */
	public ExtraStack(ParamListStandard res, int val) {
		super(res);
		stackEntry = null;
		afterStorage = StorageClass.GENERAL;
		afterBytes = -1;
	}

	public ExtraStack(StorageClass storage, int offset, ParamListStandard res)
			throws InvalidInputException {
		super(res);
		stackEntry = null;
		afterStorage = storage;
		afterBytes = offset;
		initializeEntry();
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new ExtraStack(afterStorage, afterBytes, newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}

		ExtraStack otherAction = (ExtraStack) op;

		if (afterBytes != otherAction.afterBytes || afterStorage != otherAction.afterStorage) {
			return false;
		}

		return stackEntry.isEquivalent(otherAction.stackEntry);
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		if (res.address.getAddressSpace() == stackEntry.getSpace()) {
			return SUCCESS;	// Parameter was already assigned to the stack
		}
		int grp = stackEntry.getGroup();
		// Check whether we have consumed enough storage to need to adjust stack yet
		if (afterBytes > 0) {
			int bytesConsumed = 0;
			for (int i = 0; i < resource.getNumParamEntry(); i++) {
				if (i == grp || resource.getEntry(i).getType() != afterStorage) {
					continue;
				}
				if (status[i] != 0) {
					bytesConsumed += resource.getEntry(i).getSize();
				}
			}
			if (bytesConsumed < afterBytes) {
				return SUCCESS; // Don't yet need to consume extra stack space
			}
		}
		// We assign the stack address (but ignore the actual address) updating the status for the stack,
		// which consumes the stack resources.
		ParameterPieces unused = new ParameterPieces();
		status[grp] =
			stackEntry.getAddrBySlot(status[grp], dt.getLength(), dt.getAlignment(), unused);
		return SUCCESS;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_EXTRA_STACK);
		if (afterBytes >= 0) {
			encoder.writeUnsignedInteger(ATTRIB_AFTER_BYTES, afterBytes);
		}
		if (afterStorage != StorageClass.GENERAL) {
			encoder.writeString(ATTRIB_STORAGE, afterStorage.toString());
		}
		encoder.closeElement(ELEM_EXTRA_STACK);
	}

	private void restoreAttributesXml(XmlElement el) throws XmlParseException {
		Iterator<Entry<String, String>> iter = el.getAttributes().entrySet().iterator();
		while (iter.hasNext()) {
			Entry<String, String> attrib = iter.next();
			String nm = attrib.getKey();
			if (nm.equals(ATTRIB_AFTER_BYTES.name())) {
				afterBytes = SpecXmlUtils.decodeInt(attrib.getValue());
			}
			else if (nm.equals(ATTRIB_AFTER_STORAGE.name())) {
				afterStorage = StorageClass.getClass(attrib.getValue());
			}
		}

	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_EXTRA_STACK.name());
		restoreAttributesXml(elem);
		parser.end(elem);
		try {
			initializeEntry();
		}
		catch (InvalidInputException e) {
			throw new XmlParseException(e.getMessage());
		}
	}

}
