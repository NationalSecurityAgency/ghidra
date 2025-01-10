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

import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.exception.InvalidInputException;
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
	}

	public ExtraStack(ParamListStandard res) throws InvalidInputException {
		super(res);
		stackEntry = null;
		initializeEntry();
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new ExtraStack(newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		ExtraStack otherAction = (ExtraStack) op;
		return stackEntry.isEquivalent(otherAction.stackEntry);
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		if (res.address.getAddressSpace() == stackEntry.getSpace()) {
			return SUCCESS;	// Parameter was already assigned to the stack
		}
		int grp = stackEntry.getGroup();
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
		encoder.closeElement(ELEM_EXTRA_STACK);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_EXTRA_STACK.name());
		parser.end(elem);
		try {
			initializeEntry();
		}
		catch (InvalidInputException e) {
			throw new XmlParseException(e.getMessage());
		}
	}

}
