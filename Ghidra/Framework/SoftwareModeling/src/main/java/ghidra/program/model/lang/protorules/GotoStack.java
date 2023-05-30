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
 * Action assigning a parameter Address from the next available stack location
 */
public class GotoStack extends AssignAction {

	private ParamEntry stackEntry;	// Parameter Entry corresponding to the stack

	private void initializeEntry() throws InvalidInputException {
		for (int i = 0; i < resource.getNumParamEntry(); ++i) {
			ParamEntry entry = resource.getEntry(i);
			if (!entry.isExclusion() && entry.getSpace().isStackSpace()) {
				stackEntry = entry;
				break;
			}
		}
		if (stackEntry == null) {
			throw new InvalidInputException("Cannot find matching <pentry> for action: gotostack");
		}
	}

	/**
	 * Constructor for use with restoreXml
	 * @param res is the new resource list to associate with the action
	 * @param val is a dummy argument
	 */
	protected GotoStack(ParamListStandard res, int val) {
		super(res);
		stackEntry = null;
	}

	public GotoStack(ParamListStandard res) throws InvalidInputException {
		super(res);
		stackEntry = null;
		initializeEntry();
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new GotoStack(newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		GotoStack otherAction = (GotoStack) op;
		return stackEntry.isEquivalent(otherAction.stackEntry);
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		int grp = stackEntry.getGroup();
		res.type = dt;
		status[grp] = stackEntry.getAddrBySlot(status[grp], dt.getLength(), dt.getAlignment(), res);
		return SUCCESS;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_GOTO_STACK);
		encoder.closeElement(ELEM_GOTO_STACK);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_GOTO_STACK.name());
		parser.end(elem);
		try {
			initializeEntry();
		}
		catch (InvalidInputException e) {
			throw new XmlParseException(e.getMessage());
		}
	}

}
