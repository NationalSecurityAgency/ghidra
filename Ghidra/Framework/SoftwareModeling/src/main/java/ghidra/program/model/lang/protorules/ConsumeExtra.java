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
import ghidra.xml.*;

/**
 * Consume additional registers from an alternate resource list
 * 
 * This action is a side-effect and doesn't assign an address for the current parameter.
 * The resource list, resourceType, is specified. If the side-effect is triggered,
 * register resources from this list are consumed.  If matchSize is true (the default),
 * registers are consumed, until the number of bytes in the data-type is reached.  Otherwise,
 * only a single register is consumed. If all registers are already consumed, no action is taken.
 */
public class ConsumeExtra extends AssignAction {

	private StorageClass resourceType;	// The other resource list to consume from
	private boolean matchSize;			// false, if side-effect only consumes a single register
	private ParamEntry[] tiles;			// Registers that can be consumed

	/**
	 * Cache specific ParamEntry needed by the action.
	 * Find the first ParamEntry matching the resourceType.
	 * @throws InvalidInputException if it cannot find the configured ParamEntry objects
	 */
	private void initializeEntries() throws InvalidInputException {
		tiles = resource.extractTiles(resourceType);
		if (tiles.length == 0) {
			throw new InvalidInputException(
				"Could not find matching resources for action: consume_extra");
		}
	}

	protected ConsumeExtra(ParamListStandard res) {
		super(res);
		resourceType = StorageClass.GENERAL;
		matchSize = true;
	}

	public ConsumeExtra(StorageClass store, boolean match, ParamListStandard res)
			throws InvalidInputException {
		super(res);
		resourceType = store;
		matchSize = match;
		initializeEntries();
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new ConsumeExtra(resourceType, matchSize, newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		ConsumeExtra otherAction = (ConsumeExtra) op;
		if (matchSize != otherAction.matchSize ||
			resourceType != otherAction.resourceType) {
			return false;
		}
		if (tiles.length != otherAction.tiles.length) {
			return false;
		}
		for (int i = 0; i < tiles.length; ++i) {
			if (!tiles[i].isEquivalent(otherAction.tiles[i])) {
				return false;
			}
		}
		return true;
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		int iter = 0;
		int sizeLeft = dt.getLength();
		while (sizeLeft > 0 && iter != tiles.length) {
			ParamEntry entry = tiles[iter];
			++iter;
			if (status[entry.getGroup()] != 0) {
				continue;		// Already consumed
			}
			status[entry.getGroup()] = -1;	// Consume the slot/register
			sizeLeft -= entry.getSize();
			if (!matchSize) {
				break;		// Only consume a single register
			}
		}
		return SUCCESS;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CONSUME_EXTRA);
		encoder.writeString(ATTRIB_STORAGE, resourceType.toString());
		encoder.closeElement(ELEM_CONSUME_EXTRA);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_CONSUME_EXTRA.name());
		resourceType = StorageClass.getClass(elem.getAttribute(ATTRIB_STORAGE.name()));
		parser.end(elem);
		try {
			initializeEntries();
		}
		catch (InvalidInputException e) {
			throw new XmlParseException(e.getMessage());
		}
	}

}
