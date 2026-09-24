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

import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Parameter assignment action that lets input and output parameters share stack space for
 * spilling.  Any input stack allocations can happen either before or after any
 * output stack allocation. The action can optionally add an extra stack alignment 
 * between the first allocations and second allocations.
 */
public class ShareStackAction extends SharedAction {

	private ParamEntry inputStackEntry;	// Stack resource for input parameters
	private ParamEntry outputStackEntry;	// Stack resource for output parameters
	private boolean inputFirst;	// True if input stack populated before output stack
	private int extraAlign;		// Extra alignment added between first stack allocations and second

	public ShareStackAction(PrototypeModel model) {
		super(model);
		ParamList inputResource = model.getInputResource();
		ParamList outputResource = model.getOutputResource();
		inputStackEntry = ((ParamListStandard) inputResource).getStackEntry();
		outputStackEntry = ((ParamListStandard) outputResource).getStackEntry();
	}

	@Override
	public void applyBefore(PrototypePieces proto, DataTypeManager dtManager, boolean addAutoParams,
			ArrayList<ParameterPieces> params, int[] inputStatus, int[] outputStatus) {
		if (inputFirst) {
			return;
		}
		// Treat output consumed stack as input consumed stack
		int slotnum = outputStatus[outputStackEntry.getGroup()];
		if (extraAlign > inputStackEntry.getAlign()) {
			int tmp = (slotnum * inputStackEntry.getAlign()) % extraAlign;
			if (tmp != 0) {
				slotnum += (extraAlign - tmp) / inputStackEntry.getAlign();
			}
		}
		inputStatus[inputStackEntry.getGroup()] = slotnum;
	}

	@Override
	public void applyAfter(PrototypePieces proto, DataTypeManager dtManager, boolean addAutoParams,
			ArrayList<ParameterPieces> params, int[] inputStatus, int[] outputStatus) {
		if (!inputFirst) {
			return;
		}
		if (params.isEmpty()) {
			return;
		}
		ParameterPieces outEntry = params.get(0);
		if (outEntry.address == null ||
			outEntry.address.getAddressSpace() != outputStackEntry.getSpace()) {
			return;
		}
		int slotnum = inputStatus[inputStackEntry.getGroup()];
		if (extraAlign > inputStackEntry.getAlign()) {
			int tmp = (slotnum * inputStackEntry.getAlign()) % extraAlign;
			if (tmp != 0) {
				slotnum += (extraAlign - tmp) / inputStackEntry.getAlign();
			}
		}
		inputStackEntry.getAddrBySlot(slotnum, outEntry.type.getLength(),
			outEntry.type.getAlignment(), outEntry);
	}

	@Override
	public SharedAction clone(PrototypeModel newModel) {
		return new ShareStackAction(newModel);
	}

	@Override
	public boolean isEquivalent(SharedAction obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		ShareStackAction otherAction = (ShareStackAction) obj;
		if (inputFirst != otherAction.inputFirst)
			return false;
		if (extraAlign != otherAction.extraAlign)
			return false;
		return true;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_SHARESTACK);
		encoder.writeString(ATTRIB_FIRST, inputFirst ? "input" : "output");
		if (extraAlign != 0) {
			encoder.writeUnsignedInteger(ATTRIB_ALIGN, extraAlign);
		}
		encoder.closeElement(ELEM_SHARESTACK);
	}

	@Override
	public void restoreXml(XmlPullParser parser) {
		XmlElement mainel = parser.start();
		String attribute = mainel.getAttribute(ATTRIB_FIRST.name());
		inputFirst = false;
		if (attribute != null) {
			inputFirst = attribute.equals("input");
		}
		extraAlign = SpecXmlUtils.decodeInt(mainel.getAttribute(ATTRIB_ALIGN.name()));
		parser.end(mainel);
	}
}
