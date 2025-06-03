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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a golang moduledata structure, which contains a lot of valuable bootstrapping
 * data for RTTI and function data. 
 */
@StructureMapping(structureName = "runtime.moduledata")
public class GoModuledata implements StructureMarkup<GoModuledata> {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoModuledata> structureContext;

	@FieldMapping(presentWhen = "1.16+")
	@MarkupReference
	private long pcHeader;	// pointer to the GoPcHeader instance, useful for bootstrapping.  when ver >= 1.16, this is first field

	@FieldMapping(presentWhen = "1.16+")
	private GoSlice funcnametab;	// []uint8 blob of null term strings

	@FieldMapping(presentWhen = "1.16+")
	private GoSlice cutab;	// []uint32

	@FieldMapping
	private GoSlice filetab; // []uint32 when ver <=1.15, []uint8 blob of null term strings when ver >= 1.16

	@FieldMapping(presentWhen = "1.16+")
	private GoSlice pctab;	// []uint8

	@FieldMapping
	private GoSlice pclntable;	// []uint8, shares footprint with ftab.  when ver <= 1.15, this is first field and happens to have a GoPcHeader

	@FieldMapping
	private GoSlice ftab;	// []runtime.functab, shares footprint with pclntable

	@FieldMapping
	private long data;

	@FieldMapping
	private long edata;

	@FieldMapping
	@MarkupReference
	private long text;

	@FieldMapping
	private long etext;

	@FieldMapping
	private long noptrdata;

	@FieldMapping
	private long enoptrdata;

	@FieldMapping(fieldName = "types")
	private long typesOffset;

	@FieldMapping(fieldName = "etypes")
	private long typesEndOffset;

	@FieldMapping(optional = true)
	private long gofunc;

	@FieldMapping
	private long end;

	@FieldMapping(fieldName = "typelinks")
	private GoSlice typeLinks;

	@FieldMapping
	private GoSlice itablinks; // []*runtime.itab (array of pointers to runtime.tab)

	@FieldMapping
	private GoSlice textsectmap;	// []runtime.textsect, symbol runtime.textsectionmap also points

	public GoModuledata() {
		// empty
	}

	/**
	 * Compares the data in this structure to fields in a GoPcHeader and returns true if they
	 * match.
	 * 
	 * @param otherPcHeader GoPcHeader instance
	 * @return boolean true if match, false if no match
	 */
	public boolean matchesPcHeader(GoPcHeader otherPcHeader) {
		return (!otherPcHeader.hasTextStart() || otherPcHeader.getTextStart().equals(getText())) &&
			otherPcHeader.getFuncnameAddress().equals(funcnametab.getArrayAddress());
	}

	@Markup
	public GoPcHeader getPcHeader() throws IOException {
		return pcHeader != 0 // when ver >= 1.16 
				? programContext.readStructure(GoPcHeader.class, pcHeader)
				: programContext.readStructure(GoPcHeader.class, pclntable.getArrayAddress());
	}

	public Address getPcHeaderAddress() {
		return pcHeader != 0
				? programContext.getDataAddress(pcHeader)
				: pclntable.getArrayAddress();
	}

	/**
	 * Returns the address of the beginning of the text section.
	 * 
	 * @return address of the beginning of the text section
	 */
	public Address getText() {
		return programContext.getCodeAddress(text);
	}

	public AddressRange getTextRange() {
		Address textstart = getText();
		Address textend = programContext.getCodeAddress(etext);
		return new AddressRangeImpl(textstart, textend);
	}

	public AddressRange getRoDataRange() {
		Address roStart = programContext.getCodeAddress(etext); // TODO: rodata is avail in newer govers
		Address roEnd = programContext.getCodeAddress(end);
		return new AddressRangeImpl(roStart, roEnd);
	}

	public AddressRange getDataRange() {
		Address dataStart = programContext.getCodeAddress(data);
		Address dataEnd = programContext.getCodeAddress(edata);
		return new AddressRangeImpl(dataStart, dataEnd);
	}

	/**
	 * Returns the starting offset of type info
	 * 
	 * @return starting offset of type info
	 */
	public long getTypesOffset() {
		return typesOffset;
	}

	/**
	 * Returns the ending offset of type info
	 * 
	 * @return ending offset of type info
	 */
	public long getTypesEndOffset() {
		return typesEndOffset;
	}

	/**
	 * Return the offset of the gofunc location
	 * @return offset of the gofunc location
	 */
	public long getGofunc() {
		return gofunc;
	}

	/**
	 * Reads a {@link GoFuncData} structure from the pclntable.
	 * 
	 * @param offset relative to the pclntable
	 * @return {@link GoFuncData}
	 * @throws IOException if error reading data
	 */
	public GoFuncData getFuncDataInstance(long offset) throws IOException {
		return programContext.readStructure(GoFuncData.class, pclntable.getArrayOffset() + offset);
	}

	/**
	 * Returns true if this GoModuleData is the module data that contains the specified
	 * GoFuncData structure.
	 * 
	 * @param offset offset of a GoFuncData structure
	 * @return true if this GoModuleData is the module data that contains the specified GoFuncData
	 * structure
	 */
	public boolean containsFuncDataInstance(long offset) {
		return pclntable.containsOffset(offset, 1);
	}

	/**
	 * Returns an artificial slice of the functab entries that are valid.
	 * 
	 * @return artificial slice of the functab entries that are valid
	 */
	public GoSlice getFunctabEntriesSlice() {
		// chop off the last entry as it is not a full entry (it just points to the address
		// at the end of the text segment) and can conflict with markup of the following structs
		long sliceElementCount = ftab.getLen() > 0 ? ftab.getLen() - 1 : 0;
		int entryLen =
			programContext.getStructureMappingInfo(GoFunctabEntry.class).getStructureLength();
		GoSlice subSlice = ftab.getSubSlice(0, sliceElementCount, entryLen);
		return subSlice;
	}

	/**
	 * Returns true if this module data structure contains sane values.
	 * 
	 * @return true if this module data structure contains sane values
	 */
	public boolean isValid() {
		MemoryBlock txtBlock = programContext.getGoSection("text");
		if (txtBlock != null && !txtBlock.contains(getText())) {
			return false;
		}

		MemoryBlock typelinkBlock = programContext.getGoSection("typelink");
		if (typelinkBlock != null &&
			typelinkBlock.getStart().getOffset() != typeLinks.getArrayOffset()) {
			return false;
		}

		// all these static slices should be allocated with len == cap.  If not true, fail.
		if (!typeLinks.isFull() || !filetab.isFull() || (pctab != null && !pctab.isFull()) ||
			!pclntable.isFull() || !ftab.isFull()) {
			return false;
		}

		return true;
	}

	/**
	 * Returns a slice that contains all the function names.
	 * 
	 * @return slice that contains all the function names
	 */
	public GoSlice getFuncnametab() {
		return funcnametab;
	}

	/**
	 * Returns a list of all functions contained in this module.
	 * 
	 * @return list of all functions contained in this module
	 * @throws IOException if error reading data
	 */
	public List<GoFuncData> getAllFunctionData() throws IOException {
		List<GoFunctabEntry> functabentries =
			getFunctabEntriesSlice().readList(GoFunctabEntry.class);
		List<GoFuncData> result = new ArrayList<>();
		for (GoFunctabEntry functabEntry : functabentries) {
			result.add(functabEntry.getFuncData());
		}
		return result;
	}

	/**
	 * Returns the cutab slice.
	 * 
	 * @return cutab slice
	 */
	public GoSlice getCutab() {
		return cutab;
	}

	/**
	 * Returns the filetab slice.
	 * 
	 * @return filetab slice
	 */
	public GoSlice getFiletab() {
		return filetab;
	}

	public GoSlice getPclntable() {
		return pclntable;
	}

	/**
	 * Returns the pctab slice.
	 * 
	 * @return pctab slice
	 */
	public GoSlice getPctab() {
		return pctab;
	}

	public GoSlice getPcValueTable() {
		return pctab != null ? pctab : pclntable;
	}

	/**
	 * Returns a reference to the controlling {@link GoRttiMapper go binary} context.
	 * 
	 * @return reference to the controlling {@link GoRttiMapper go binary} context
	 */
	public GoRttiMapper getGoBinary() {
		return programContext;
	}

	@Override
	public StructureContext<GoModuledata> getStructureContext() {
		return structureContext;
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException, CancelledException {
		typeLinks.markupArray("moduledata.typeLinks", null,
			programContext.getGoTypes().getInt32DT(), false, session);
		typeLinks.markupElementReferences(4, getTypeList(), session);

		itablinks.markupArray("moduledata.itablinks", null, GoItab.class, true, session);

		if (funcnametab != null) {
			markupStringTable(funcnametab.getArrayAddress(), funcnametab.getLen(), session);
		}
		markupStringTable(filetab.getArrayAddress(), filetab.getLen(), session);

		GoSlice subSlice = getFunctabEntriesSlice();
		subSlice.markupArray("moduledata.ftab", null, GoFunctabEntry.class, false, session);
		subSlice.markupArrayElements(GoFunctabEntry.class, session);

		Structure textsectDT =
			programContext.getGoTypes().getGhidraDataType("runtime.textsect", Structure.class);
		if (textsectDT != null) {
			textsectmap.markupArray("runtime.textsectionmap", null, textsectDT, false, session);
		}
	}

	/**
	 * Returns a list of the GoItabs present in this module.
	 * 
	 * @return list of the GoItabs present in this module
	 * @throws IOException if error reading data
	 */
	@Markup
	public List<GoItab> getItabs() throws IOException {
		List<GoItab> result = new ArrayList<>();

		long[] itabAddrs = itablinks.readUIntList(programContext.getPtrSize());
		for (long itabAddr : itabAddrs) {
			GoItab itab = programContext.readStructure(GoItab.class, itabAddr);
			result.add(itab);
		}

		return result;
	}

	private void markupStringTable(Address addr, long stringTableLength, MarkupSession session) {
		DataType stringDT = StringUTF8DataType.dataType;
		long startOfString = addr.getOffset();
		long endOfStringTable = startOfString + stringTableLength;
		BinaryReader reader = programContext.getReader(startOfString);
		try {
			while (startOfString < endOfStringTable) {
				reader.readNextUtf8String(); // don't care about string, just stream position after read
				long len = reader.getPointerIndex() - startOfString;
				if (len > 0 && len < Integer.MAX_VALUE) {
					Address stringAddr = addr.getNewAddress(startOfString);
					session.markupAddress(stringAddr, stringDT, (int) len);
				}
				startOfString = reader.getPointerIndex();
			}
		}
		catch (IOException e) {
			Msg.warn(this, "Failed when marking up string table at: " + addr, e);
		}
	}

	/**
	 * Returns a list of locations of the types contained in this module.
	 * 
	 * @return list of addresses of GoType structures
	 * @throws IOException if error reading data 
	 */
	public List<Address> getTypeList() throws IOException {
		long[] typeOffsets = typeLinks.readUIntList(4 /* always sizeof(int32) */);
		Address typesBaseAddr = programContext.getDataAddress(typesOffset);
		List<Address> result = Arrays.stream(typeOffsets)
				.mapToObj(offset -> typesBaseAddr.add(offset))
				.toList();
		return result;
	}

	//--------------------------------------------------------------------------------------------
	/**
	 * Returns an easily found first GoModuledata instance.
	 * 
	 * @param context already initialized {@link GoRttiMapper}
	 * @return new GoModuledata instance, or null if not found
	 * @throws IOException if error reading found structure
	 */
	/* package */ static GoModuledata getFirstModuledata(GoRttiMapper context)
			throws IOException {
		Program program = context.getProgram();
		Symbol firstModuleDataSymbol = GoRttiMapper.getGoSymbol(program, "runtime.firstmoduledata");
		if (firstModuleDataSymbol == null) {
			return null;
		}
		return context.readStructure(GoModuledata.class, firstModuleDataSymbol.getAddress());
	}

	/**
	 * Searches memory for a likely GoModuledata structure.
	 * 
	 * @param context already initialized {@link GoRttiMapper}
	 * @param pcHeaderAddress address of an already found {@link GoPcHeader}
	 * @param pcHeader the {@link GoPcHeader}
	 * @param range memory range to search.  Will be different for different types of binaries
	 * @param monitor {@link TaskMonitor} 
	 * @return new GoModuledata instance, or null if not found
	 * @throws IOException if error reading found structure
	 */
	/* package */ static GoModuledata findFirstModule(GoRttiMapper context,
			Address pcHeaderAddress, GoPcHeader pcHeader, AddressRange range, TaskMonitor monitor)
			throws IOException {
		if (range == null) {
			return null;
		}

		Program program = context.getProgram();
		Memory memory = program.getMemory();

		// Search memory for a pointer to the pclntab struct.  The result should be the first
		// field of the GoModuledata structure.
		int ptrSize = context.getPtrSize();
		byte[] searchBytes = new byte[ptrSize];
		context.getDataConverter().putValue(pcHeaderAddress.getOffset(), ptrSize, searchBytes, 0);
		Address moduleAddr = memory.findBytes(range.getMinAddress(), range.getMaxAddress(),
			searchBytes, null, true, monitor);
		if (moduleAddr == null) {
			return null;
		}

		GoModuledata moduleData = context.readStructure(GoModuledata.class, moduleAddr);

		// Verify that we read a good GoModuledata struct by comparing some of its values to
		// the pclntab structure.
		return moduleData.matchesPcHeader(pcHeader) ? moduleData : null;
	}
}
