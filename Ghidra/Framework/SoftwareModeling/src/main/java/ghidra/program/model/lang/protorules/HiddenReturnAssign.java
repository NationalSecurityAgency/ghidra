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

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Allocate the return value as special input register
 * 
 * The assignAddress() method signals with hiddenret_specialreg, indicating that the
 * input register assignMap() method should use storage class TYPECLASS_HIDDENRET to assign
 * an additional input register to hold a pointer to the return value.  This is different than
 * the default hiddenret action that assigns a location based TYPECLASS_PTR and generally
 * consumes a general purpose input register.
 */
public class HiddenReturnAssign extends AssignAction {

	private int retCode;		// The specific signal to pass back

	public HiddenReturnAssign(ParamListStandard res, boolean voidLock) {
		super(res);
		retCode = voidLock ? HIDDENRET_SPECIALREG_VOID : HIDDENRET_SPECIALREG;
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new HiddenReturnAssign(newResource, retCode == HIDDENRET_SPECIALREG_VOID);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		HiddenReturnAssign otherOp = (HiddenReturnAssign) op;
		return (retCode == otherOp.retCode);
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		return retCode;	// Signal to assignMap to use TYPECLASS_HIDDENRET
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_HIDDEN_RETURN);
		if (retCode == HIDDENRET_SPECIALREG_VOID) {
			encoder.writeBool(ATTRIB_VOIDLOCK, true);
		}
		encoder.closeElement(ELEM_HIDDEN_RETURN);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		retCode = HIDDENRET_SPECIALREG;
		XmlElement elem = parser.start(ELEM_HIDDEN_RETURN.name());
		String voidLockString = elem.getAttribute(ATTRIB_VOIDLOCK.name());
		if (SpecXmlUtils.decodeBoolean(voidLockString)) {
			retCode = HIDDENRET_SPECIALREG_VOID;
		}
		parser.end(elem);
	}
}
