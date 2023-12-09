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
 * An action that assigns an Address to a function prototype parameter
 * 
 * A request for the address of either return storage or an input parameter is made
 * through the assignAddress() method, which is given full information about the function prototype.
 * Details about how the action performs is configured through the restoreXml() method.
 */
public abstract class AssignAction {
	public static final int SUCCESS = 0;			// Data-type is fully assigned
	public static final int FAIL = 1;				// Action could not be applied (not enough resources)
	public static final int HIDDENRET_PTRPARAM = 2;	// Hidden return pointer as first input parameter
	public static final int HIDDENRET_SPECIALREG = 3;	// Hidden return pointer in special register
	public static final int HIDDENRET_SPECIALREG_VOID = 4;	// Hidden return pointer, but no normal return

	protected ParamListStandard resource;			// Resources to which this action applies

	public AssignAction(ParamListStandard res) {
		resource = res;
	}

	/**
	 *  Make a copy of this action
	* @param newResource is the new resource object that will own the clone
	* @return the newly allocated copy
	 * @throws InvalidInputException if required configuration is not present in new resource object
	*/
	public abstract AssignAction clone(ParamListStandard newResource) throws InvalidInputException;

	/**
	 * Test if the given action is configured and performs identically to this
	 * @param op is the given action
	 * @return true if the two actions are equivalent
	 */
	public abstract boolean isEquivalent(AssignAction op);

	/**
	 * Assign an address and other meta-data for a specific parameter or for return storage in context
	 * The Address is assigned based on the data-type of the parameter, available register
	 * resources, and other details of the function prototype.  Consumed resources are marked.
	 * This method returns a response code:
	 *   - SUCCESS            - indicating the Address was successfully assigned
	 *   - FAIL               - if the Address could not be assigned
	 *   - HIDDENRET_PTRPARAM - if an additional hidden return parameter is required
	* @param dt is the data-type of the parameter or return value
	* @param proto is the high-level description of the function prototype
	* @param pos is the position of the parameter (pos>=0) or return storage (pos=-1)
	* @param dtManager is a data-type manager for (possibly) transforming the data-type
	* @param status is the resource consumption array
	* @param res will hold the resulting description of the parameter
	* @return the response code
	*/
	public abstract int assignAddress(DataType dt, PrototypePieces proto, int pos,
			DataTypeManager dtManager, int[] status, ParameterPieces res);

	/**
	 * Save this action and its configuration to a stream
	 * @param encoder is the stream encoder
	 * @throws IOException for problems writing to the stream
	 */
	public abstract void encode(Encoder encoder) throws IOException;

	/**
	 * Configure any details of how this action should behave from the stream
	 * @param parser is the given stream decoder
	 * @throws XmlParseException is there are problems decoding the stream
	 */
	public abstract void restoreXml(XmlPullParser parser) throws XmlParseException;

	/**
	 * Read the next action element from the stream and return the new configured
	 * AssignAction object.  If the next element is not an action, throw an exception.
	 * @param parser is the stream parser
	 * @param res is the resource set for the new action
	 * @return the new action
	 * @throws XmlParseException for problems parsing the stream
	 */
	static public AssignAction restoreActionXml(XmlPullParser parser, ParamListStandard res)
			throws XmlParseException {
		AssignAction action;
		XmlElement elemId = parser.peek();
		String nm = elemId.getName();
		if (nm.equals(ELEM_GOTO_STACK.name())) {
			action = new GotoStack(res, 0);
		}
		else if (nm.equals(ELEM_JOIN.name())) {
			action = new MultiSlotAssign(res);
		}
		else if (nm.equals(ELEM_CONSUME.name())) {
			action = new ConsumeAs(StorageClass.GENERAL, res);
		}
		else if (nm.equals(ELEM_CONVERT_TO_PTR.name())) {
			action = new ConvertToPointer(res);
		}
		else if (nm.equals(ELEM_HIDDEN_RETURN.name())) {
			action = new HiddenReturnAssign(res, false);
		}
		else if (nm.equals(ELEM_JOIN_PER_PRIMITIVE.name())) {
			boolean consumeMostSig = res.getEntry(0).isBigEndian();
			action = new MultiMemberAssign(StorageClass.GENERAL, false, consumeMostSig, res);
		}
		else {
			throw new XmlParseException("Unknown model rule action: " + nm);
		}
		action.restoreXml(parser);
		return action;
	}

	/**
	 * Read the next sideeffect element from the stream and return the new configured
	 * AssignAction object.  If the next element is not a sideeffect, throw an exception.
	 * @param parser is the stream parser
	 * @param res is the resource set for the new sideeffect
	 * @return the new sideeffect
	 * @throws XmlParseException for problems parsing the stream
	 */
	static public AssignAction restoreSideeffectXml(XmlPullParser parser, ParamListStandard res)
			throws XmlParseException {
		AssignAction action;
		XmlElement elemId = parser.peek();
		String nm = elemId.getName();

		if (nm.equals(ELEM_CONSUME_EXTRA.name())) {
			action = new ConsumeExtra(res);
		}
		else {
			throw new XmlParseException("Unknown model rule sideeffect: " + nm);
		}
		action.restoreXml(parser);
		return action;
	}

}
