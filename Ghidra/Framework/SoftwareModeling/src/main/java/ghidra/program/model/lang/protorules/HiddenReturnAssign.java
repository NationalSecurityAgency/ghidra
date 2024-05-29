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
 * Allocate the return value as an input parameter
 * 
 * A pointer to where the return value is to be stored is passed in as an input parameter.
 * This action signals this by returning one of
 *   - HIDDENRET_PTRPARAM         - indicating the pointer is allocated as a normal input parameter
 *   - HIDDENRET_SPECIALREG       - indicating the pointer is passed in a dedicated register
 *   - HIDDENRET_SPECIALREG_VOID
 * 
 * Usually, if a hidden return input is present, the normal register used for return
 * will also hold the pointer at the point(s) where the function returns.  A signal of
 * HIDDENRET_SPECIALREG_VOID indicates the normal return register is not used to pass back
 * the pointer.
 */
public class HiddenReturnAssign extends AssignAction {

	static public final String STRATEGY_SPECIAL = "special";	// Return pointer in special reg
	static public final String STRATEGY_NORMAL = "normalparam";	// Return pointer as normal param

	private int retCode;		// The specific signal to pass back

	public HiddenReturnAssign(ParamListStandard res, int code) {
		super(res);
		retCode = code;
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new HiddenReturnAssign(newResource, retCode);
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
		if (retCode == HIDDENRET_PTRPARAM) {
			encoder.writeString(ATTRIB_STRATEGY, STRATEGY_NORMAL);
		}
		else if (retCode == HIDDENRET_SPECIALREG_VOID) {
			encoder.writeBool(ATTRIB_VOIDLOCK, true);
		}
		encoder.closeElement(ELEM_HIDDEN_RETURN);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		retCode = HIDDENRET_SPECIALREG;
		XmlElement elem = parser.start(ELEM_HIDDEN_RETURN.name());
		String strategyString = elem.getAttribute(ATTRIB_STRATEGY.name());
		if (strategyString != null) {
			if (strategyString.equals(STRATEGY_NORMAL)) {
				retCode = HIDDENRET_PTRPARAM;
			}
			else if (strategyString.equals(STRATEGY_SPECIAL)) {
				retCode = HIDDENRET_SPECIALREG;
			}
			else {
				throw new XmlParseException("Bad <hidden_return> strategy: " + strategyString);
			}
		}
		String voidLockString = elem.getAttribute(ATTRIB_VOIDLOCK.name());
		if (SpecXmlUtils.decodeBoolean(voidLockString)) {
			retCode = HIDDENRET_SPECIALREG_VOID;
		}
		parser.end(elem);
	}
}
