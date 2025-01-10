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
import java.util.Map.Entry;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.protorules.PrimitiveExtractor.Primitive;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Consume multiple registers from different storage classes to pass a data-type
 * 
 * This action is for calling conventions that can use both floating-point and general purpose registers
 * when assigning storage for a single composite data-type, such as the X86-64 System V ABI
 */
public class MultiSlotDualAssign extends AssignAction {
	private StorageClass baseType;		// Resource list from which to consume general tiles
	private StorageClass altType;		// Resource list from which to consume alternate tiles
	private boolean consumeMostSig;		// True if resources are consumed starting with most significant bytes
	private boolean justifyRight;		// True if initial bytes are padding for odd data-type sizes
	private int tileSize;				// Number of bytes in a tile
	private ParamEntry[] baseTiles;		// General registers for joining
	private ParamEntry[] altTiles;		// Alternate registers for joininig

	/**
	 * Find the first ParamEntry matching the baseType, and the first matching altType.
	 * @throws InvalidInputException if the required elements are not available in the resource list
	 */
	private void initializeEntries() throws InvalidInputException {
		baseTiles = resource.extractTiles(baseType);
		altTiles = resource.extractTiles(altType);
		if (baseTiles.length == 0 || altTiles.length == 0) {
			throw new InvalidInputException(
				"Could not find matching resources for action: join_dual_class");
		}
		tileSize = baseTiles[0].getSize();
		if (tileSize != altTiles[0].getSize()) {
			throw new InvalidInputException(
				"Storage class register sizes do not match for action: join_dual_class");
		}
	}

	/**
	 * Get the first unused ParamEntry within a given tileset
	 * @param iter points to the starting entry to search
	 * @param tiles is the given tileset
	 * @param status is the usage information for the entries
	 * @return the iterator to the unused ParamEntry
	 */
	private int getFirstUnused(int iter, ParamEntry[] tiles, int[] status) {
		for (; iter != tiles.length; ++iter) {
			ParamEntry entry = tiles[iter];
			if (status[entry.getGroup()] != 0) {
				continue;		// Already consumed
			}
			return iter;
		}
		return tiles.length;
	}

	/**
	 * Get the storage class to use for the specific section of the data-type
	 * 
	 * For the section starting at -off- extending through -tileSize- bytes, if any primitive
	 * overlaps the boundary of the section, return -1. Otherwise, if all the primitive data-types
	 * in the section match the alternate storage class, return 1, or if one or more does not
	 * match, return 0. The -index- of the first primitive after the start of the section is
	 * provided and is then updated to be the first primitive after the end of the section.
	 * @param primitives is the list of primitive data-types making up the data-type
	 * @param off is the starting offset of the section
	 * @param index is the index of the first primitive in the section
	 * @return 0 for a base tile, 1 for an alternate tile, -1 for boundary overlaps
	 */
	private int getTileClass(PrimitiveExtractor primitives, int off, int[] index) {
		int res = 1;
		int count = 0;
		int endBoundary = off + tileSize;
		while (index[0] < primitives.size()) {
			Primitive element = primitives.get(index[0]);
			if (element.offset < off) {
				return -1;
			}
			if (element.offset >= endBoundary) {
				break;
			}
			if (element.offset + element.dt.getLength() > endBoundary) {
				return -1;
			}
			count += 1;
			index[0] += 1;
			StorageClass storage = ParamEntry.getBasicTypeClass(element.dt);
			if (storage != altType) {
				res = 0;
			}
		}
		if (count == 0) {
			return -1;	// Must be at least one primitive in section
		}
		return res;
	}

	/**
	 * Constructor for use with decode. Set default configuration.
	 * @param res is the new resource set to associate with this action
	 */
	protected MultiSlotDualAssign(ParamListStandard res) {
		super(res);
		baseType = StorageClass.GENERAL;	// Tile from general purpose registers
		altType = StorageClass.FLOAT;	// Use specialized registers for floating-point components
		consumeMostSig = false;
		justifyRight = false;
		if (res.getEntry(0).isBigEndian()) {
			consumeMostSig = true;
			justifyRight = true;
		}
		tileSize = 0;
	}

	public MultiSlotDualAssign(StorageClass baseStore, StorageClass altStore, boolean mostSig,
			boolean justRight, ParamListStandard res) throws InvalidInputException {
		super(res);
		baseType = baseStore;
		altType = altStore;
		consumeMostSig = mostSig;
		justifyRight = justRight;
		initializeEntries();
	}

	@Override
	public AssignAction clone(ParamListStandard newResource) throws InvalidInputException {
		return new MultiSlotDualAssign(baseType, altType, consumeMostSig, justifyRight,
			newResource);
	}

	@Override
	public boolean isEquivalent(AssignAction op) {
		if (this.getClass() != op.getClass()) {
			return false;
		}
		MultiSlotDualAssign otherAction = (MultiSlotDualAssign) op;
		if (consumeMostSig != otherAction.consumeMostSig ||
			justifyRight != otherAction.justifyRight) {
			return false;
		}
		if (baseType != otherAction.baseType || altType != otherAction.altType) {
			return false;
		}
		if (baseTiles.length != otherAction.baseTiles.length) {
			return false;
		}
		for (int i = 0; i < baseTiles.length; ++i) {
			if (!baseTiles[i].isEquivalent(otherAction.baseTiles[i])) {
				return false;
			}
		}
		if (altTiles.length != otherAction.altTiles.length) {
			return false;
		}
		for (int i = 0; i < altTiles.length; ++i) {
			if (!altTiles[i].isEquivalent(otherAction.altTiles[i])) {
				return false;
			}
		}
		return true;
	}

	@Override
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		PrimitiveExtractor primitives = new PrimitiveExtractor(dt, false, 0, 1024);
		if (!primitives.isValid() || primitives.size() == 0 || primitives.containsHoles()) {
			return FAIL;
		}
		ParameterPieces param = new ParameterPieces();
		int[] primitiveIndex = new int[1];
		primitiveIndex[0] = 0;
		int[] tmpStatus = status.clone();
		ArrayList<Varnode> pieces = new ArrayList<>();
		int typeSize = dt.getLength();
		int sizeLeft = typeSize;
		int iterBase = 0;
		int iterAlt = 0;
		while (sizeLeft > 0) {
			int iterType = getTileClass(primitives, typeSize - sizeLeft, primitiveIndex);
			if (iterType < 0) {
				return FAIL;
			}
			ParamEntry entry;
			if (iterType == 0) {
				iterBase = getFirstUnused(iterBase, baseTiles, tmpStatus);
				if (iterBase == baseTiles.length) {
					return FAIL;		// Out of general registers
				}
				entry = baseTiles[iterBase];
			}
			else {
				iterAlt = getFirstUnused(iterAlt, altTiles, tmpStatus);
				if (iterAlt == altTiles.length) {
					return FAIL;		// Out of alternate registers
				}
				entry = altTiles[iterAlt];
			}
			int trialSize = entry.getSize();
			entry.getAddrBySlot(tmpStatus[entry.getGroup()], trialSize, 1, param);
			tmpStatus[entry.getGroup()] = -1;	// Consume the register
			Varnode vn = new Varnode(param.address, trialSize);
			pieces.add(vn);
			sizeLeft -= trialSize;
		}
		if (sizeLeft < 0) {			// Have odd data-type size
			if (justifyRight) {
				// Initial bytes of first entry are padding
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
		res.assignAddressFromPieces(pieces, consumeMostSig, false, resource.getLanguage());
		return SUCCESS;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_JOIN_DUAL_CLASS);
		if (resource.getEntry(0).isBigEndian() != justifyRight) {
			encoder.writeBool(ATTRIB_REVERSEJUSTIFY, true);
		}
		if (baseType != StorageClass.GENERAL) {
			encoder.writeString(ATTRIB_STORAGE, baseType.toString());
		}
		if (altType != StorageClass.FLOAT) {
			encoder.writeString(ATTRIB_B, altType.toString());
		}
		encoder.closeElement(ELEM_JOIN);
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws XmlParseException {
		XmlElement elem = parser.start(ELEM_JOIN_DUAL_CLASS.name());
		for (Entry<String, String> attrib : elem.getAttributes().entrySet()) {
			String name = attrib.getKey();
			if (name.equals(ATTRIB_REVERSEJUSTIFY.name())) {
				if (SpecXmlUtils.decodeBoolean(attrib.getValue())) {
					justifyRight = !justifyRight;
				}
			}
			else if (name.equals(ATTRIB_STORAGE.name()) || name.equals(ATTRIB_A.name())) {
				baseType = StorageClass.getClass(attrib.getValue());
			}
			else if (name.equals(ATTRIB_B.name())) {
				altType = StorageClass.getClass(attrib.getValue());
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
