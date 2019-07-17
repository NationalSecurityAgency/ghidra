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
package ghidra.app.util.datatype.microsoft;

import java.util.*;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassTranslator;
import ghidra.util.exception.AssertException;

public class WEVTResourceDataType extends DynamicDataType {

	static {
		ClassTranslator.put("ghidra.app.plugin.prototype.data.WEVTResourceDataType",
			WEVTResourceDataType.class.getName());
	}

	public WEVTResourceDataType() {
		this(null, "WEVTResource", null);
	}

	public WEVTResourceDataType(DataTypeManager dtm) {
		this(null, "WEVTResource", dtm);
	}

	protected WEVTResourceDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}

	@Override
	public String getDescription() {
		return "WEVT (Windows Event Template) stored as a Resource";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "WEVTRes";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return "WEVT";
	}

	//Signatures for the main header, event provider header, and for the various provider element types
	private byte[] crimSig = { (byte) 'C', (byte) 'R', (byte) 'I', (byte) 'M' }; //CRIM
	private byte[] wevtSig = { (byte) 'W', (byte) 'E', (byte) 'V', (byte) 'T' }; //WEVT
	private byte[] keywSig = { (byte) 'K', (byte) 'E', (byte) 'Y', (byte) 'W' }; //KEYW
	private byte[] levlSig = { (byte) 'L', (byte) 'E', (byte) 'V', (byte) 'L' }; //LEVL
	private byte[] mapsSig = { (byte) 'M', (byte) 'A', (byte) 'P', (byte) 'S' }; //MAPS
	private byte[] chanSig = { (byte) 'C', (byte) 'H', (byte) 'A', (byte) 'N' }; //CHAN
	private byte[] vmapSig = { (byte) 'V', (byte) 'M', (byte) 'A', (byte) 'P' }; //VMAP
	private byte[] bmapSig = { (byte) 'B', (byte) 'M', (byte) 'A', (byte) 'P' }; //BMAP
	private byte[] evntSig = { (byte) 'E', (byte) 'V', (byte) 'N', (byte) 'T' }; //EVNT
	private byte[] opcoSig = { (byte) 'O', (byte) 'P', (byte) 'C', (byte) 'O' }; //OPCO
	private byte[] taskSig = { (byte) 'T', (byte) 'A', (byte) 'S', (byte) 'K' }; //TASK
	private byte[] ttblSig = { (byte) 'T', (byte) 'T', (byte) 'B', (byte) 'L' };//TTBL
	private byte[] tempSig = { (byte) 'T', (byte) 'E', (byte) 'M', (byte) 'P' }; //TEMP

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer mbIn) {
		List<DataTypeComponent> comps = new ArrayList<>();
		MemBuffer memBuffer = mbIn;
		int tempOffset = 0;
		ArrayList<Integer> eventOffsets = new ArrayList<Integer>();
		int numEventProviders;

		ArrayList<Integer> providerElementDescriptors = new ArrayList<Integer>();
		ArrayList<Integer> providerElementOffsets = new ArrayList<Integer>();
		int currentProviderElement = 0;

		//check first signature "CRIM" and if valid attempt to add all of the components to the WEVT structure
		if (checkMagic(crimSig, memBuffer, tempOffset)) {

			try {
				//first get the number of event providers from the main header and add the main WEVT header
				numEventProviders = memBuffer.getInt(tempOffset + 12);
				tempOffset =
					addComp(createWEVTStructureHeader(), 16, "WEVT_Template Header",
						memBuffer.getAddress(), comps, tempOffset);

				//add array of event provider descriptors - the number of them and the offsets to them are in the main WEVT header we just got
				StructureDataType epd =
					createEventProviderDescriptor(memBuffer, tempOffset, eventOffsets);
				if (epd == null) {
					Msg.debug(this,
						"Error applying Windows Event template (WEVT) resource data type.");
					return null;
				}

				ArrayDataType EPDArray = new ArrayDataType(epd, numEventProviders, 20);
				tempOffset =
					addComp(EPDArray, 20 * numEventProviders,
						"Array of Event Provider Descriptors",
						memBuffer.getAddress().add(tempOffset), comps, tempOffset);

				StructureDataType eventProvider =
					createEventProviderStructure(memBuffer, tempOffset, providerElementDescriptors,
						providerElementOffsets);

				tempOffset =
					addComp(eventProvider, eventProvider.getLength(), "Event Provider Structure",
						memBuffer.getAddress().add(tempOffset), comps, tempOffset);

				//Loop over all the Event Provider Descriptors
				for (int j = 0; j < providerElementDescriptors.size(); j++) {
					// Loop over all the Event Providers in each Descriptor
					for (int i = 0; i < providerElementDescriptors.get(j); i++) {

						//get the offset of the current provider element
						int lastUsedOffset = tempOffset;
						tempOffset = providerElementOffsets.get(currentProviderElement);

						if (lastUsedOffset < tempOffset) {
							int diff = tempOffset - lastUsedOffset;
							ArrayDataType padding =
								new ArrayDataType(ByteDataType.dataType, diff, 1);
							tempOffset =
								addComp(padding, diff, "padding",
									memBuffer.getAddress().add(lastUsedOffset), comps,
									lastUsedOffset);
						}

						//check to make sure there is a valid signature there
						byte[] bytes = new byte[4];
						memBuffer.getBytes(bytes, tempOffset);

						tempOffset = processProviderElement(bytes, memBuffer, tempOffset, comps);
						if (tempOffset < 0) {
							Msg.debug(this, "Error processing Provider Element.");
							return null;
						}
						currentProviderElement++;
					}

				}

			}
			catch (MemoryAccessException e1) {
				Msg.debug(this, "Error applying Windows Event template (WEVT) resource data type.");
			}
		}
		else {
			Msg.debug(this, "Not a valid Windows Event template (WEVT) resource data type");
			return null;
		}
		DataTypeComponent[] result = comps.toArray(new DataTypeComponent[comps.size()]);
		return result;
	}

	//This is the first thing in a WEVT_TEMPLATE Resource
	private StructureDataType createWEVTStructureHeader() {

		StructureDataType struct = new StructureDataType("WEVT_Header", 0);

		struct.add(StringDataType.dataType, 4, "Signature", "");//CRIM
		struct.add(UnsignedIntegerDataType.dataType, 4, "Size", "");
		struct.add(ShortDataType.dataType, 2, "MajorVersion", "");
		struct.add(ShortDataType.dataType, 2, "MinorVersion", "");
		struct.add(UnsignedIntegerDataType.dataType, 4, "Number of event providers", "");

		return struct;
	}

	//An array of these follow the main header - these each contain an offset to an event provider
	private StructureDataType createEventProviderDescriptor(MemBuffer memBuffer, int tempOffset,
			ArrayList<Integer> eventOffsets) throws MemoryAccessException {

		StructureDataType struct = new StructureDataType("Event Provider Descriptor", 0);

		GuidDataType guidID = new GuidDataType();
		struct.add(guidID, 16, "Provider Identifier GUID", "");

		//get the offset from the main top
		int offset = memBuffer.getInt(tempOffset + 16);

		//compute the address of that offset
		Address offsetAddr = memBuffer.getAddress().add(offset);

		struct.add(DWordDataType.dataType, 4, "Provider Data Offset", "Provider Data Address: " +
			offsetAddr.toString());

		eventOffsets.add(memBuffer.getInt(tempOffset));
		return struct;

	}

	//An array of these follows the event provider descriptor array - each is pointed to by the corresponding item in that array
	private StructureDataType createEventProviderStructure(MemBuffer memBuffer, int tempOffset,
			ArrayList<Integer> providerElementDescriptors, ArrayList<Integer> providerElementOffsets)
			throws MemoryAccessException {

		if (!checkMagic(wevtSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid WEVT signature");
		}

		StructureDataType struct = new StructureDataType("Event Provider", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "WEVT");
		struct.add(UnsignedIntegerDataType.dataType, 4, "Size", "including the header");
		struct.add(DWordDataType.dataType, 4, "Message-table identifier", "(-1 if not set)");
		tempOffset += 12;
		struct.add(UnsignedIntegerDataType.dataType, 4, "Number of provider element descriptors",
			"");

		int currentPEDNumber = memBuffer.getInt(tempOffset);

		providerElementDescriptors.add(currentPEDNumber);
		tempOffset += 4;
		struct.add(UnsignedIntegerDataType.dataType, 4, "Number of Unknown 32-bit values", "");

		//Get the number of unknown dwords - know how many but not what they are for 
		int numUnknownValues = memBuffer.getInt(tempOffset);

		numUnknownValues *= 4;

		tempOffset += 4;

		for (int i = 0; i < currentPEDNumber; i++) {
			struct.add(
				createProviderElementDescriptorStructure(memBuffer, tempOffset,
					providerElementOffsets), "Provider Element Descriptor", "");
			tempOffset += 8;
		}

		ArrayDataType unknown32bit =
			new ArrayDataType(DWordDataType.dataType, numUnknownValues / 4, 4);
		struct.add(unknown32bit, numUnknownValues, "Unknown 32-bit values", "");
		tempOffset += numUnknownValues;

		return struct;
	}

	private StructureDataType createProviderElementDescriptorStructure(MemBuffer memBuffer,
			int tempOffset, ArrayList<Integer> providerElementOffsets) throws MemoryAccessException { //8
		StructureDataType struct = new StructureDataType("Provider Element Descriptor", 0);

		int offset = memBuffer.getInt(tempOffset);

		Address provElementAddr = memBuffer.getAddress().add(offset);
		struct.add(DWordDataType.dataType, 4, "Provider element offset",
			"Provider Element Address: " + provElementAddr.toString());

		providerElementOffsets.add(memBuffer.getInt(tempOffset));

		struct.add(DWordDataType.dataType, 4, "Unknown", "");
		return struct;
	}

	private StructureDataType createKeywordStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {

		int keyworddefinitions = 0;
		ArrayList<Integer> keywordDataOffsets = new ArrayList<Integer>();

		if (!checkMagic(keywSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid KEYW signature");
		}

		StructureDataType struct = new StructureDataType("Keyword Definitions", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "KEYW");
		struct.add(IntegerDataType.dataType, 4, "Size", "");
		tempOffset += 8;
		struct.add(IntegerDataType.dataType, 4, "Number of keyword definitions", "");

		keyworddefinitions = memBuffer.getInt(tempOffset);
		tempOffset += 4;

		for (int i = 0; i < keyworddefinitions; i++) {
			struct.add(createKeywordDefStructure(memBuffer, tempOffset), "Keyword definitions", "");
			int dataOffset = memBuffer.getInt(tempOffset + 12);
			keywordDataOffsets.add(dataOffset);
			tempOffset += 16;
		}
		for (int i = 0; i < keyworddefinitions; i++) {
			tempOffset = keywordDataOffsets.get(i);
			struct.add(createKeywordDataStructure(memBuffer, tempOffset), "Keyword data", "");
		}

		return struct;
	}

	private StructureDataType createKeywordDefStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Keyword definitions", 0);
		struct.add(QWordDataType.dataType, 8, "Identifier", "(Bitmask)");
		struct.add(DWordDataType.dataType, 4, "Message-table identifier", "");
		tempOffset += 12;

		int dataOffset = memBuffer.getInt(tempOffset);

		Address dataOffsetAddress = memBuffer.getAddress().add(dataOffset);
		struct.add(DWordDataType.dataType, 4, "Data offset", "Data offset address: " +
			dataOffsetAddress.toString());
		tempOffset += 4;
		return struct;
	}

	private StructureDataType createKeywordDataStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Keyword data", 0);
		struct.add(DWordDataType.dataType, 4, "size", "");

		int size = memBuffer.getInt(tempOffset);

		struct.add(UnicodeDataType.dataType, size - 4, "keyword data", "");
		tempOffset += size; //includes int and string
		return struct;
	}

	private StructureDataType createLevelStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {

		ArrayList<Integer> leveloffsets = new ArrayList<Integer>();
		int leveldefinitions = 0;

		if (!checkMagic(levlSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid LEVL signature");
		}

		StructureDataType struct = new StructureDataType("Level Definitions", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "LEVL");
		struct.add(IntegerDataType.dataType, 4, "Size", "includes size of the header, 0 if empty");
		tempOffset += 8;
		struct.add(IntegerDataType.dataType, 4, "Number of level definitions", "");

		leveldefinitions = memBuffer.getInt(tempOffset);
		tempOffset += 4;
		for (int i = 0; i < leveldefinitions; i++) {
			struct.add(createLevelDefStructure(memBuffer, tempOffset),
				"Level Definition Structure", "");
			leveloffsets.add(memBuffer.getInt(tempOffset + 8));
			tempOffset += 12;
		}
		for (int i = 0; i < leveldefinitions; i++) {
			int levelDataSize = memBuffer.getInt(tempOffset);
			int offset = leveloffsets.get(i);
			struct.add(createLevelDataStructure(memBuffer, offset), "Level Data Structure", "");
			tempOffset += levelDataSize;
		}
		return struct;
	}

	private StructureDataType createLevelDefStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Level Definition", 0);
		struct.add(DWordDataType.dataType, 4, "Identifier", "");
		struct.add(DWordDataType.dataType, 4, "Message-table identifier", "");
		tempOffset += 8;
		int offset = memBuffer.getInt(tempOffset);
		Address levelDataAddr = memBuffer.getAddress().add(offset);

		struct.add(DWordDataType.dataType, 4, "Data offset",
			"Level Data Address: " + levelDataAddr.toString());

		tempOffset += 4;
		return struct;
	}

	private StructureDataType createLevelDataStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {//size
		StructureDataType struct = new StructureDataType("Level Data", 0);
		struct.add(DWordDataType.dataType, 4, "Size", "");

		int size = memBuffer.getInt(tempOffset);

		struct.add(UnicodeDataType.dataType, size - 4, "data", "");
		tempOffset += size; //includes int and string
		return struct;
	}

	private StructureDataType createMapsDefStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {

		int numMapDefs = 0;
		ArrayList<Integer> mapsDefsOffsets = new ArrayList<Integer>();
		ArrayList<Integer> mapStringDataOffsets = new ArrayList<Integer>(); //offsets of map strings

		if (!checkMagic(mapsSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid MAPS signature");
		}

		StructureDataType struct = new StructureDataType("Maps Definitions", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "MAPS");
		struct.add(DWordDataType.dataType, 4, "Size", "");
		tempOffset += 8;
		struct.add(DWordDataType.dataType, 4, "Number of map definitions", "");

		numMapDefs = memBuffer.getInt(tempOffset);
		tempOffset += 4;

		//Get MAP definition data offsets (online doc is wrong - it does actually include the first one)
		for (int i = 0; i < numMapDefs; i++) {
			int offset = memBuffer.getInt(tempOffset);
			Address offsetAddr = memBuffer.getAddress().add(offset);
			struct.add(DWordDataType.dataType, 4, "Map definition offset", "Offset Address: " +
				offsetAddr.toString());
			mapsDefsOffsets.add(offset);
			tempOffset += 4;
		}

		//add all map definitions at correct offsets
		for (int i = 0; i < numMapDefs; i++) {
			tempOffset = mapsDefsOffsets.get(i);

			if (checkMagic(vmapSig, memBuffer, tempOffset)) {
				struct.add(createValueMapDefStructure(memBuffer, tempOffset, mapStringDataOffsets));
			}
			else if (checkMagic(bmapSig, memBuffer, tempOffset)) {
				struct.add(createBMapDefStructure(memBuffer, tempOffset));
			}
			else {
				throw new AssertException(
					"Error applying WEVT Resource Data Type - Invalid VMAP or BMAP signature");
			}
		}
		for (int i = 0; i < mapStringDataOffsets.size(); i++) {
			tempOffset = mapStringDataOffsets.get(i);
			struct.add(createMapStringStructure(memBuffer, tempOffset));
		}

		return struct;
	}

	private StructureDataType createValueMapDefStructure(MemBuffer memBuffer, int tempOffset,
			ArrayList<Integer> mapStringDataOffsets) throws MemoryAccessException {

		int numVMAPEntries = 0;
		StructureDataType struct = new StructureDataType("Value Map Definition", 0);

		struct.add(StringDataType.dataType, 4, "Signature", "VMAP");
		struct.add(DWordDataType.dataType, 4, "Size", "");
		tempOffset += 8;

		struct.add(DWordDataType.dataType, 4, "Map string data offset", "");

		mapStringDataOffsets.add(memBuffer.getInt(tempOffset));
		tempOffset += 4;

		struct.add(DWordDataType.dataType, 4, "Unknown", "Unknown");

		tempOffset += 4;
		struct.add(DWordDataType.dataType, 4, "Number of value map entries", "");

		numVMAPEntries = memBuffer.getInt(tempOffset);
		tempOffset += 4;

		for (int i = 0; i < numVMAPEntries; i++) {
			struct.add(createValueMapEntryStructure(memBuffer, tempOffset), 8, "Value map entry",
				"");
		}

		return struct;
	}

	//I couldn't find info about this structure
	//Based on all the others, I assume size is the first thing after the signature
	//I also couldn't find any examples with one of these in it so I can't verify or test
	//TODO: Update when the format is determined
	private StructureDataType createBMapDefStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("BMAP Map Definition", 0);

		struct.add(StringDataType.dataType, 4, "Signature", "BMAP");
		tempOffset += 4;

		struct.add(DWordDataType.dataType, 4, "Size", "");

		int size = memBuffer.getInt(tempOffset);
		tempOffset += 4;

		ArrayDataType unknown = new ArrayDataType(ByteDataType.dataType, size - 8, 1);
		struct.add(unknown.getDataType(), size - 8, "Rest of BMAP structure", "Unknown format");

		tempOffset += (size - 8);

		return struct;
	}

	private StructureDataType createValueMapEntryStructure(MemBuffer memBuffer, int tempOffset) {
		StructureDataType struct = new StructureDataType("Value Map Entry", 0);
		struct.add(DWordDataType.dataType, 4, "Identifier", "");
		struct.add(DWordDataType.dataType, 4, "Message-table identifier", "");
		tempOffset += 8;
		return struct;
	}

	private StructureDataType createMapStringStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException { //add to mapstruct

		StructureDataType struct = new StructureDataType("Map String", 0);
		struct.add(DWordDataType.dataType, 4, "Size", "");

		int size = memBuffer.getInt(tempOffset);
		struct.add(UnicodeDataType.dataType, size - 4, "Map String", "");
		tempOffset += size;

		return struct;
	}

	private StructureDataType createChannelStruct(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {

		ArrayList<Integer> channelDataOffsets = new ArrayList<Integer>();
		//	ArrayList<Integer> channelDataSizes = new ArrayList<Integer>();

		if (!checkMagic(chanSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid CHAN signature");
		}

		StructureDataType struct = new StructureDataType("Channel Definition Structure", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "CHAN");
		struct.add(IntegerDataType.dataType, 4, "Size", "");
		tempOffset += 8;
		struct.add(IntegerDataType.dataType, 4, "Number of channel definitions", "");

		int channeldefs = memBuffer.getInt(tempOffset);
		tempOffset += 4;

		for (int i = 0; i < channeldefs; i++) {
			struct.add(createChannelDefStructure(memBuffer, tempOffset, channelDataOffsets), 16,
				"Channel Definition", "");
			tempOffset += 16;
		}

		for (int i = 0; i < channelDataOffsets.size(); i++) {
			if (tempOffset < channelDataOffsets.get(i)) {
				//if the current offset is less than the next data to be laid down, figure out how much padding is needed and lay it down
				int diff = channelDataOffsets.get(i) - tempOffset;
				ArrayDataType padding = new ArrayDataType(ByteDataType.dataType, diff, 1);
				struct.add(padding.getDataType(), diff, "Padding", "");
				//then update the current offset to the correct location so that the data can be laid down
				tempOffset = channelDataOffsets.get(i);
			}
			int channelDataSize = memBuffer.getInt(tempOffset);
			struct.add(createChannelDataStructure(memBuffer, tempOffset), channelDataSize,
				"Channel Data", "");
			tempOffset += channelDataSize;
		}
		return struct;
	}

	private StructureDataType createChannelDefStructure(MemBuffer memBuffer, int tempOffset,
			ArrayList<Integer> channelDataOffsets) throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Channel Definition", 0);
		struct.add(DWordDataType.dataType, 4, "Identifier", "");
		tempOffset += 4;

		//compute address of channel data 
		int offset = memBuffer.getInt(tempOffset);
		Address channelDataAddr = memBuffer.getAddress().add(offset);

		struct.add(DWordDataType.dataType, 4, "Data Offset", "Channel Data Address: " +
			channelDataAddr.toString());

		channelDataOffsets.add(memBuffer.getInt(tempOffset));
		tempOffset += 4;

		struct.add(DWordDataType.dataType, 4, "Unknown", "");
		struct.add(DWordDataType.dataType, 4, "Message-table identifier", "");
		tempOffset += 8;
		return struct;
	}

	private StructureDataType createChannelDataStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Channel Data", 0);
		struct.add(DWordDataType.dataType, 4, "Size", "");
		int size = memBuffer.getInt(tempOffset);
		struct.add(UnicodeDataType.dataType, size - 4, "Channel Data String", "");
		return struct;
	}

	private StructureDataType createEventDefStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {

		ArrayList<Integer> unknownDwordsOffsetList = new ArrayList<Integer>();
		ArrayList<Integer> numUnknownDwordsList = new ArrayList<Integer>();

		if (!checkMagic(evntSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid EVNT signature");
		}

		StructureDataType struct = new StructureDataType("Event Definitions Structure", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "EVNT");
		struct.add(IntegerDataType.dataType, 4, "Size", "");
		tempOffset += 8;
		struct.add(IntegerDataType.dataType, 4, "Number of event definitions", "");

		int eventdefs = memBuffer.getInt(tempOffset);
		tempOffset += 4;
		struct.add(DWordDataType.dataType, 4, "Unknown", "");
		tempOffset += 4;

		for (int i = 0; i < eventdefs; i++) {
			struct.add(
				createEventDefinitionStructure(memBuffer, tempOffset, unknownDwordsOffsetList,
					numUnknownDwordsList), "Event Definition", "");
			tempOffset += 48;
		}

		//This last section is made up of sets of dwords - each structure in the previous section lists a number of dwords and an offset to them
		//these values have been stored in the two lists used below
		for (int i = 0; i < eventdefs; i++) {
			if (numUnknownDwordsList.get(i) > 0) {
				tempOffset = unknownDwordsOffsetList.get(i);
				for (int j = 0; j < numUnknownDwordsList.get(i); j++) {
					struct.add(DWordDataType.dataType, 4, "Unknown Dword # " + i, "");
					tempOffset += 4;
				}
			}
		}
		return struct;
	}

	//This was not well defined in the document so just add the known pieces + rest as array for now
	private StructureDataType createEventDefinitionStructure(MemBuffer memBuffer, int tempOffset,
			ArrayList<Integer> unknownDwordsOffsetList, ArrayList<Integer> numUnknownDwordsList)
			throws MemoryAccessException {
		String offsetString = new String();
		StructureDataType struct = new StructureDataType("Event Definitions", 0);
		struct.add(WordDataType.dataType, 2, "Identifier", "");
		tempOffset += 2;

		ArrayDataType eventDef = new ArrayDataType(ByteDataType.dataType, 6, 1);
		struct.add(eventDef, 6, "Unknown Format", "");
		tempOffset += 6;

		ArrayDataType keywords = new ArrayDataType(ByteDataType.dataType, 8, 1);
		struct.add(keywords, 8, "Keywords", "");
		tempOffset += 8;

		struct.add(DWordDataType.dataType, 4, "Message Identifier", "");
		tempOffset += 4;

		int templateDefOffset = memBuffer.getInt(tempOffset);
		offsetString = getOffsetAddressString(templateDefOffset, memBuffer);
		struct.add(DWordDataType.dataType, 4, "Template Definition Offset", offsetString);
		tempOffset += 4;

		int opCodeDefOffset = memBuffer.getInt(tempOffset);
		offsetString = getOffsetAddressString(opCodeDefOffset, memBuffer);
		struct.add(DWordDataType.dataType, 4, "Opcode Definition Offset", offsetString);
		tempOffset += 4;

		int levelDefOffset = memBuffer.getInt(tempOffset);
		offsetString = getOffsetAddressString(levelDefOffset, memBuffer);
		struct.add(DWordDataType.dataType, 4, "Level Definition Offset", offsetString);
		tempOffset += 4;

		int taskDefOffset = memBuffer.getInt(tempOffset);
		offsetString = getOffsetAddressString(taskDefOffset, memBuffer);
		struct.add(DWordDataType.dataType, 4, "Task Definition Offset", offsetString);
		tempOffset += 4;

		int numDwordsInLastSection = memBuffer.getInt(tempOffset);
		numUnknownDwordsList.add(numDwordsInLastSection);

		struct.add(DWordDataType.dataType, 4, "Number of Dwords in Next Section", "");
		tempOffset += 4;

		int lastEventSectionOffset = memBuffer.getInt(tempOffset);
		offsetString = getOffsetAddressString(lastEventSectionOffset, memBuffer);
		unknownDwordsOffsetList.add(lastEventSectionOffset);

		struct.add(DWordDataType.dataType, 4, "Offset to Dwords in Next Section", offsetString);
		tempOffset += 4;
		struct.add(DWordDataType.dataType, 4, "Unknown (Flags)", "");
		tempOffset += 4;
		return struct;
	}

	private String getOffsetAddressString(int offset, MemBuffer memBuffer) {
		String offsetString = new String();
		if (offset > 0) {
			Address offsetAddr = memBuffer.getAddress().add(offset);
			offsetString = offsetString.concat("Address: " + offsetAddr.toString());
		}
		else {
			offsetString = "No offset";
		}
		return offsetString;
	}

	private StructureDataType createOpcodeStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {

		if (!checkMagic(opcoSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid OPCO signature");
		}

		StructureDataType struct = new StructureDataType("Opcode Definition Structure", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "OPCO");
		struct.add(IntegerDataType.dataType, 4, "Size", "includes the header, empty if 0");
		tempOffset += 8;
		struct.add(IntegerDataType.dataType, 4, "Number of opcode definitions", "");

		int opcodedefs = memBuffer.getInt(tempOffset);
		int[] opcodeDataOffsets = new int[opcodedefs];
		tempOffset += 4;
		for (int i = 0; i < opcodedefs; i++) {
			opcodeDataOffsets[i] = memBuffer.getInt(tempOffset + 8);
			struct.add(createOpcodeDefStructure(memBuffer, tempOffset), 12, "Opcode Definition", "");
			tempOffset += 12;

		}
		for (int i = 0; i < opcodedefs; i++) {
			tempOffset = opcodeDataOffsets[i];
			struct.add(createOpcodeDataStructure(memBuffer, tempOffset), "Opcode Data", "");
		}

		return struct;
	}

	private StructureDataType createOpcodeDefStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Opcode Definition", 0);
		struct.add(DWordDataType.dataType, 4, "Identifier", "");
		struct.add(DWordDataType.dataType, 4, "Message-table identifier", "");
		tempOffset += 8;
		int offset = memBuffer.getInt(tempOffset);
		Address opcodeDataAddr = memBuffer.getAddress().add(offset);
		struct.add(DWordDataType.dataType, 4, "Data offset", "Data Opcode Address: " +
			opcodeDataAddr.toString());

		tempOffset += 4;
		return struct;
	}

	private StructureDataType createOpcodeDataStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Opcode Data", 0);
		struct.add(IntegerDataType.dataType, 4, "Size", "Including the size itself");

		int size = memBuffer.getInt(tempOffset);
		struct.add(UnicodeDataType.dataType, size - 4, "Opcode Data String", "");
		tempOffset += size;
		return struct;
	}

	private StructureDataType createTaskStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {

		ArrayList<Integer> taskDataOffsets = new ArrayList<Integer>();
		int taskdefs;

		if (!checkMagic(taskSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid TASK signature");
		}

		StructureDataType struct = new StructureDataType("Task Definition Structure", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "TASK");
		struct.add(IntegerDataType.dataType, 4, "Size", "");
		tempOffset += 8;
		struct.add(IntegerDataType.dataType, 4, "Number of task definitions", "");

		taskdefs = memBuffer.getInt(tempOffset);
		tempOffset += 4;

		for (int i = 0; i < taskdefs; i++) {
			ArrayDataType taskdefinitions =
				new ArrayDataType(createTaskDefStructure(memBuffer, tempOffset), taskdefs, 28);

			struct.add(taskdefinitions.getDataType(), 28, "Task Definition", "");
			int dataOffset = memBuffer.getInt(tempOffset + 24);
			taskDataOffsets.add(dataOffset);
			tempOffset += 28;
		}
		for (int i = 0; i < taskdefs; i++) {
			tempOffset = taskDataOffsets.get(i);
			struct.add(createTaskDataStructure(memBuffer, tempOffset), "Task Data Structure", "");

		}
		return struct;
	}

	private StructureDataType createTaskDefStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Task definition", 0);
		struct.add(DWordDataType.dataType, 4, "Identifier", "");
		struct.add(DWordDataType.dataType, 4, "Message-table identifier", "");

		GuidDataType guidID = new GuidDataType();
		struct.add(guidID, 16, "MUI Identifier GUID", "");

		tempOffset += 24;

		int dataOffset = memBuffer.getInt(tempOffset);

		Address dataOffsetAddr = memBuffer.getAddress().add(dataOffset);
		struct.add(DWordDataType.dataType, 4, "Data offset", "Data offset address: " +
			dataOffsetAddr.toString());

		tempOffset += 4;

		return struct;
	}

	private StructureDataType createTaskDataStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Task Data", 0);
		struct.add(IntegerDataType.dataType, 4, "Size", "");

		int size = memBuffer.getInt(tempOffset);

		struct.add(UnicodeDataType.dataType, size - 4, "Task Data", "");
		tempOffset += size;
		return struct;
	}

	private StructureDataType createTemplateTableStructure(MemBuffer memBuffer, int tempOffset)
			throws MemoryAccessException {

		if (!checkMagic(ttblSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid TTBL signature");
		}

		StructureDataType struct = new StructureDataType("Template Table", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "TTBL");
		struct.add(IntegerDataType.dataType, 4, "Size", "Including template table header");
		tempOffset += 8;

		struct.add(IntegerDataType.dataType, 4, "Number of templates", "");

		int templates = memBuffer.getInt(tempOffset);
		tempOffset += 4;

		for (int i = 0; i < templates; i++) {
			int tempDefSize = memBuffer.getInt(tempOffset + 4);
			struct.add(createTemplateDefStructure(memBuffer, tempOffset, tempDefSize));
			tempOffset += tempDefSize;
		}

		return struct;
	}

	//figure out this format at some point - it isn't fully defined in the document used
	private StructureDataType createTemplateDefStructure(MemBuffer memBuffer, int tempOffset,
			int tempDefSize) throws MemoryAccessException {

		if (!checkMagic(tempSig, memBuffer, tempOffset)) {
			throw new AssertException(
				"Error applying WEVT Resource Data Type - Invalid TEMP signature");
		}

		StructureDataType struct = new StructureDataType("Template Definition", 0);
		struct.add(StringDataType.dataType, 4, "Signature", "TEMP");
		tempOffset += 4;

		struct.add(IntegerDataType.dataType, 4, "Size", "Including the template header");
		tempOffset += 4;

		int numVariableDescriptors = memBuffer.getInt(tempOffset);
		struct.add(IntegerDataType.dataType, 4, "Number of variable descriptors", "");
		tempOffset += 4;

		int numVariableNames = memBuffer.getInt(tempOffset);
		struct.add(IntegerDataType.dataType, 4, "Number of variable names", "");
		tempOffset += 4;

		int instanceVariablesOffset = memBuffer.getInt(tempOffset);
		struct.add(DWordDataType.dataType, 4, "Instance variables offset", "address = " +
			memBuffer.getAddress().add(instanceVariablesOffset).toString());
		tempOffset += 4;

		struct.add(DWordDataType.dataType, 4, "Unknown (# BinXML fragments?)", "");
		tempOffset += 4;

		GuidDataType guidID = new GuidDataType();
		struct.add(guidID, 16, "Identifier GUID", "");

		tempOffset += 16;

		int bxmlLen = instanceVariablesOffset - tempOffset;
		ArrayDataType binaryXMLArray = new ArrayDataType(ByteDataType.dataType, bxmlLen, 1);
		struct.add(binaryXMLArray.getDataType(), bxmlLen, "Binary XML", "");
		tempOffset += bxmlLen;

		tempOffset = instanceVariablesOffset;

		ArrayList<Integer> instanceNamesOffsetList = new ArrayList<Integer>();
		for (int i = 0; i < numVariableDescriptors; i++) {
			struct.add(createTemplateInstanceVariableDescriptorStructure(memBuffer, tempOffset),
				20, "", "");
			int namesOffset = memBuffer.getInt(tempOffset + 16);
			instanceNamesOffsetList.add(namesOffset);
			tempOffset += 20;
		}

		for (int i = 0; i < numVariableNames; i++) {
			tempOffset = instanceNamesOffsetList.get(i);
			struct.add(createTemplateInstanceVariableNameStructure(memBuffer, tempOffset));
		}

		return struct;
	}

	private StructureDataType createTemplateInstanceVariableDescriptorStructure(
			MemBuffer memBuffer, int tempOffset) throws MemoryAccessException {

		StructureDataType struct =
			new StructureDataType("Template Instance Variable Descriptor", 0);
		struct.add(DWordDataType.dataType, 4, "Unknown", "");
		struct.add(ByteDataType.dataType, 1, "Value type", "");
		struct.add(ByteDataType.dataType, 1, "Unknown", "");
		struct.add(WordDataType.dataType, 2, "Unknown", "");
		struct.add(DWordDataType.dataType, 4, "Unknown", "");
		struct.add(DWordDataType.dataType, 4, "Unknown", "");
		tempOffset += 16;

		int offset = memBuffer.getInt(tempOffset);

		Address namesOffsetAddr = memBuffer.getAddress().add(offset);
		struct.add(DWordDataType.dataType, 4, "Template instance variable name offset",
			"Address Offset: " + namesOffsetAddr.toString());
		tempOffset += 4;

		return struct;

	}

	private StructureDataType createTemplateInstanceVariableNameStructure(MemBuffer memBuffer,
			int tempOffset) throws MemoryAccessException {
		StructureDataType struct = new StructureDataType("Template Instance Variable Name", 0);
		struct.add(IntegerDataType.dataType, 4, "Size", "");

		int size = memBuffer.getInt(tempOffset);

		struct.add(UnicodeDataType.dataType, size - 4, "Name String", "");

		return struct;
	}

	private boolean checkMagic(byte[] sigBytes, MemBuffer memBuffer, int tempOffset) {
		try {
			for (int i = 0; i < sigBytes.length; i++) {
				if (sigBytes[i] != (memBuffer.getByte(tempOffset + i))) {
					return false;
				}
			}
		}
		catch (MemoryAccessException e) {
			Msg.debug(this, "Incorrect signature for a WEVT resource");
		}
		return true;
	}

	private int processProviderElement(byte[] sigBytes, MemBuffer memBuffer, int tempOffset,
			List<DataTypeComponent> comps) throws MemoryAccessException {

		int newOffset = -1;
		if (Arrays.equals(sigBytes, keywSig)) {
			StructureDataType struct = createKeywordStructure(memBuffer, tempOffset);
			newOffset =
				addComp(struct, struct.getLength(), "Keyword Definition",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else if (Arrays.equals(sigBytes, levlSig)) {
			StructureDataType struct = createLevelStructure(memBuffer, tempOffset);
			newOffset =
				addComp(struct, struct.getLength(), "Level Definition",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else if (Arrays.equals(sigBytes, mapsSig)) {
			StructureDataType struct = createMapsDefStructure(memBuffer, tempOffset);
			newOffset =
				addComp(struct, struct.getLength(), "Maps Definition",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else if (Arrays.equals(sigBytes, chanSig)) {
			StructureDataType struct = createChannelStruct(memBuffer, tempOffset);
			newOffset =
				addComp(struct, struct.getLength(), "Channel Definition",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else if (Arrays.equals(sigBytes, evntSig)) {
			StructureDataType struct = createEventDefStructure(memBuffer, tempOffset);
			newOffset =
				addComp(struct, struct.getLength(), "Event Definition",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else if (Arrays.equals(sigBytes, opcoSig)) {
			StructureDataType struct = createOpcodeStructure(memBuffer, tempOffset);
			newOffset =
				addComp(struct, struct.getLength(), "Opcode Definition",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else if (Arrays.equals(sigBytes, taskSig)) {

			StructureDataType struct = createTaskStructure(memBuffer, tempOffset);
			newOffset =
				addComp(struct, struct.getLength(), "Task Definition",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else if (Arrays.equals(sigBytes, ttblSig)) {
			StructureDataType struct = createTemplateTableStructure(memBuffer, tempOffset);
			newOffset =
				addComp(struct, struct.getLength(), "Template Table Definition",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else {
			return -1;
		}

		return newOffset;
	}

	private int addComp(DataType dataType, int length, String fieldName, Address address,
			List<DataTypeComponent> comps, int currentOffset) {
		if (length > 0) {
			ReadOnlyDataTypeComponent readOnlyDataTypeComponent =
				new ReadOnlyDataTypeComponent(dataType, this, length, comps.size(), currentOffset,
					fieldName, null);
			comps.add(readOnlyDataTypeComponent);
			currentOffset += length;
		}
		return currentOffset;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<WEVT-Resource>";
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "WEVT";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new WEVTResourceDataType(dtm);
	}

}
