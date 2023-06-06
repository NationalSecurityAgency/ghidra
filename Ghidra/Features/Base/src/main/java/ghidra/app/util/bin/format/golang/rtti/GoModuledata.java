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
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.golang.rtti.types.GoType;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a golang moduledata structure, which contains a lot of invaluable bootstrapping
 * data for RTTI and function data. 
 */
@StructureMapping(structureName = "runtime.moduledata")
public class GoModuledata implements StructureMarkup<GoModuledata> {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoModuledata> structureContext;

	@FieldMapping
	@MarkupReference
	private long pcHeader;	// pointer to the GoPcHeader instance, useful for bootstrapping

	@FieldMapping
	@MarkupReference
	private long text;

	@FieldMapping(fieldName = "types")
	private long typesOffset;

	@FieldMapping(fieldName = "etypes")
	private long typesEndOffset;

	@FieldMapping(fieldName = "typelinks")
	private GoSlice typeLinks;

	@FieldMapping
	private GoSlice funcnametab;	// []uint8 blob of null term strings

	@FieldMapping
	private GoSlice cutab;	// []uint32

	@FieldMapping
	private GoSlice filetab; // []uint8 blob of null term strings

	@FieldMapping
	private GoSlice pctab;	// []uint8

	@FieldMapping
	private GoSlice pclntable;	// []uint8, shares footprint with ftab

	@FieldMapping
	private GoSlice ftab;	// []runtime.functab, shares footprint with pclntable

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
	 * @param pclntab GoPcHeader instance
	 * @return boolean true if match, false if no match
	 */
	public boolean matchesPclntab(GoPcHeader pclntab) {
		return (!pclntab.hasTextStart() || pclntab.getTextStart().equals(getText())) &&
			pclntab.getFuncnameAddress().equals(funcnametab.getArrayAddress());
	}

	@Markup
	public GoPcHeader getPcHeader() throws IOException {
		return programContext.readStructure(GoPcHeader.class, pcHeader);
	}

	public Address getText() {
		return programContext.getCodeAddress(text);
	}

	public long getTypesOffset() {
		return typesOffset;
	}

	public long getTypesEndOffset() {
		return typesEndOffset;
	}

	public GoFuncData getFuncDataInstance(long offset) throws IOException {
		return programContext.readStructure(GoFuncData.class, pclntable.getArrayOffset() + offset);
	}

	public boolean containsFuncDataInstance(long offset) {
		return pclntable.isOffsetWithinData(offset, 1);
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

	public boolean isValid() {
		MemoryBlock txtBlock = programContext.getProgram().getMemory().getBlock(".text");
		if (txtBlock != null && txtBlock.getStart().getOffset() != text) {
			return false;
		}

		MemoryBlock typelinkBlock = programContext.getProgram().getMemory().getBlock(".typelink");
		if (typelinkBlock != null &&
			typelinkBlock.getStart().getOffset() != typeLinks.getArrayOffset()) {
			return false;
		}

		// all these static slices should be allocated with len == cap.  If not true, fail.
		if (!typeLinks.isFull() || !filetab.isFull() || !pctab.isFull() || !pclntable.isFull() ||
			!ftab.isFull()) {
			return false;
		}

		return true;
	}

	public GoSlice getFuncnametab() {
		return funcnametab;
	}

	public List<GoFuncData> getAllFunctionData() throws IOException {
		List<GoFunctabEntry> functabentries =
			getFunctabEntriesSlice().readList(GoFunctabEntry.class);
		List<GoFuncData> result = new ArrayList<>();
		for (GoFunctabEntry functabEntry : functabentries) {
			result.add(functabEntry.getFuncData());
		}
		return result;
	}

	@Override
	public StructureContext<GoModuledata> getStructureContext() {
		return structureContext;
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException {
		typeLinks.markupArray("moduledata.typeLinks", programContext.getInt32DT(), false, session);
		typeLinks.markupElementReferences(4, getTypeList(), session);

		itablinks.markupArray("moduledata.itablinks", GoItab.class, true, session);

		markupStringTable(funcnametab.getArrayAddress(), funcnametab.getLen(), session);
		markupStringTable(filetab.getArrayAddress(), filetab.getLen(), session);

		GoSlice subSlice = getFunctabEntriesSlice();
		subSlice.markupArray("moduledata.ftab", GoFunctabEntry.class, false, session);
		subSlice.markupArrayElements(GoFunctabEntry.class, session);

		Structure textsectDT =
			programContext.getGhidraDataType("runtime.textsect", Structure.class);
		if (textsectDT != null) {
			textsectmap.markupArray("runtime.textsectionmap", textsectDT, false, session);
		}
	}

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

	@Markup
	public Iterator<GoType> iterateTypes() throws IOException {
		return getTypeList().stream()
				.map(addr -> {
					try {
						return programContext.getGoType(addr);
					}
					catch (IOException e) {
						return null;
					}
				})
				.filter(Objects::nonNull)
				.iterator();
	}

	public List<Address> getTypeList() throws IOException {
		long[] typeOffsets = typeLinks.readUIntList(4 /* always sizeof(int32) */);
		Address typesBaseAddr = programContext.getDataAddress(typesOffset);
		List<Address> result = Arrays.stream(typeOffsets)
				.mapToObj(offset -> typesBaseAddr.add(offset))
				.collect(Collectors.toList());
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
		Symbol firstModuleDataSymbol =
			SymbolUtilities.getUniqueSymbol(program, "runtime.firstmoduledata");
		if (firstModuleDataSymbol == null) {
			return null;
		}
		return context.readStructure(GoModuledata.class, firstModuleDataSymbol.getAddress());
	}

	/**
	 * Searches memory for a likely GoModuledata structure.
	 * 
	 * @param context already initialized {@link GoRttiMapper}
	 * @param pclntabAddress address of an already found {@link GoPcHeader}
	 * @param pclntab the {@link GoPcHeader}
	 * @param range memory range to search.  Will be different for different types of binaries
	 * @param monitor {@link TaskMonitor} 
	 * @return new GoModuledata instance, or null if not found
	 * @throws IOException if error reading found structure
	 */
	/* package */ static GoModuledata findFirstModule(GoRttiMapper context,
			Address pclntabAddress, GoPcHeader pclntab, AddressRange range, TaskMonitor monitor)
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
		context.getDataConverter().putValue(pclntabAddress.getOffset(), ptrSize, searchBytes, 0);
		Address moduleAddr = memory.findBytes(range.getMinAddress(), range.getMaxAddress(),
			searchBytes, null, true, monitor);
		if (moduleAddr == null) {
			return null;
		}

		GoModuledata moduleData = context.readStructure(GoModuledata.class, moduleAddr);

		// Verify that we read a good GoModuledata struct by comparing some of its values to
		// the pclntab structure.
		return moduleData.matchesPclntab(pclntab) ? moduleData : null;
	}
}

/*
struct runtime.moduledata Length:276 Alignment:4{
  runtime.pcHeader*pcHeader
  []uint8                                                  funcnametab      
  []uint32                                                cutab                 
  []uint8                                                  filetab                 
  []uint8                                                  pctab                 
  []uint8                                                  pclntable            
  []runtime.functab                                ftab
uintptr                                  findfunctab
uintptr                                  minpc
uintptr                                  maxpc
uintptr                                  text
uintptr                                  etext
uintptr                                  noptrdata
uintptr                                  enoptrdata
uintptr                                  data
uintptr                                  edata
uintptr                                  bss
uintptr                                  ebss
uintptr                                  noptrbss
uintptr                                  enoptrbss
uintptr                                  end
uintptr                                  gcdata
uintptr                                  gcbss
uintptr                                  types
uintptr                                  etypes
uintptr                                  rodata
uintptr                                  gofunc                
  []runtime.textsect                              textsectmap       
  []int32                                                  typelinks             
  []*runtime.itab                                    itablinks             
  []
runtime.ptabEntry ptab
string                                                   pluginpath          
  []runtime.modulehash                           pkghashes
string                                                   modulename      
  []runtime.modulehash                           modulehashes
uint8                                     hasmain
runtime.bitvector                                gcdatamask
runtime.bitvector                                gcbssmask map[runtime.typeOff]*runtime._type  typemap
bool                                                       bad runtime.moduledata*next
}pack()*/
