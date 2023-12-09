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

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.exception.InvalidInputException;
import ghidra.xml.*;

/**
 * Action converting the parameter's data-type to a pointer, and assigning storage for the pointer.
 * This assumes the data-type is stored elsewhere and only the pointer is passed as a parameter.
 */
public class ConvertToPointer extends AssignAction {

	private AddressSpace space;	// Address space used for pointer size

	public ConvertToPointer(ParamListStandard res) {
		super(res);
		space = res.getSpacebase();
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new ConvertToPointer(newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		ConvertToPointer otherAction = (ConvertToPointer) op;
		if (space == null && otherAction.space == null) {
			return true;
		}
		if (space == null || otherAction.space == null) {
			return false;
		}
		if (!space.equals(otherAction.space)) {
			return false;
		}
		return true;
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {

		int pointersize = proto.model.getPointerSize(space);

		// Convert the data-type to a pointer
		DataType pointertp = dtManager.getPointer(dt, pointersize);
		// (Recursively) assign storage
		int responseCode = resource.assignAddress(pointertp, proto, pos, dtManager, status, res);
		res.isIndirect = true;
		return responseCode;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CONVERT_TO_PTR);
		encoder.closeElement(ELEM_CONVERT_TO_PTR);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_CONVERT_TO_PTR.name());
		parser.end(elem);
	}

}
