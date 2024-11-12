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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.golang.GoConstants;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.framework.store.LockException;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;

/**
 * A structure that golang generates that contains metadata about a function.
 */
@StructureMapping(structureName = "runtime._func")
public class GoFuncData implements StructureMarkup<GoFuncData> {

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoFuncData> context;

	@FieldMapping(presentWhen = "1.18+", fieldName = { "entryoff", "entryOff" })
	@EOLComment("getDescription")
	@MarkupReference("getFuncAddress")
	private long entryoff;	// relative offset of function

	@FieldMapping(presentWhen = "-1.17")
	@EOLComment("getDescription")
	@MarkupReference("getFuncAddress")
	private long entry;	// absolute location of function

	@FieldMapping(fieldName = { "nameoff", "nameOff" })
	@MarkupReference("getNameAddress")
	private long nameoff;	// uint32

	//private long args; // size of arguments

	@FieldMapping
	@MarkupReference("getDeferreturnAddress")
	private long deferreturn;

	@FieldMapping
	private long pcfile;	// offset in moduledata.pctab where file info starts

	@FieldMapping
	private long pcln;		// offset in moduledata.pctab where line num info starts

	@FieldMapping
	private int npcdata; // number of elements in varlen pcdata array

	@FieldMapping(presentWhen = "1.16+")
	private long cuOffset = -1;

	@FieldMapping
	private byte funcID;

	@FieldMapping(presentWhen = "1.17+")
	@EOLComment("flags")
	private byte flag;	// runtime.funcFlag, see GoFuncFlag enum

	@FieldMapping
	private int nfuncdata;	// number of elements in varlen funcdata array

	//--------------------------------------------------------------------------------------

	private Address funcAddress;	// set when entryoff or entry are set

	/**
	 * Sets the function's entry point via a relative offset value
	 * <p>
	 * Called via deserialization for entryoff fieldmapping annotation
	 * 
	 * @param entryoff relative offset to function
	 */
	public void setEntryoff(long entryoff) {
		this.entryoff = entryoff;

		GoModuledata moduledata = getModuledata();
		this.funcAddress = moduledata != null ? moduledata.getText().add(entryoff) : null;
		this.entry = funcAddress != null ? funcAddress.getOffset() : -1;
	}

	/**
	 * Sets the absolute entry address.
	 * <p>
	 * Called via deserialization for entry fieldmapping annotation
	 * 
	 * @param entry absolute value.
	 */
	public void setEntry(long entry) {
		this.entry = entry;
		this.funcAddress = context.getDataTypeMapper().getCodeAddress(entry);
	}

	/**
	 * Returns the address of this function.
	 * 
	 * @return the address of this function
	 */
	public Address getFuncAddress() {
		return funcAddress;
	}

	/**
	 * Returns the address range of this function's body, recovered by examining addresses in the
	 * function's pc-to-filename translation table, or if not present, a single address range
	 * that contains the function's entry point.
	 * 
	 * @return {@link AddressRange} representing the function's known footprint
	 */
	public AddressRange getBody() {
		// find the body of a function by looking at its pc-to-filename translation table and
		// using the max pc value
		try {
			long max = new GoPcValueEvaluator(this, pcfile).getMaxPC() - 1;
			if (max > entry) {
				return new AddressRangeImpl(funcAddress, funcAddress.getNewAddress(max));
			}
		}
		catch (IOException e) {
			// fall thru, return 1-byte range
		}
		return new AddressRangeImpl(funcAddress, funcAddress);
	}

	/**
	 * Returns the Ghidra function that corresponds to this go function.
	 * 
	 * @return Ghidra {@link Function}, or null if there is no Ghidra function at the address
	 */
	public Function getFunction() {
		Address addr = getFuncAddress();
		return programContext.getProgram().getFunctionManager().getFunctionAt(addr);
	}

	public Address getDeferreturnAddress() {
		return deferreturn != 0 ? getFuncAddress().add(deferreturn) : null;
	}

	private long getPcDataStartOffset(int tableIndex) {
		return context.getStructureLength() + (4 /*size(int32)*/ * tableIndex);
	}

	private long getPcDataStart(int tableIndex) throws IOException {
		return context.getFieldReader(getPcDataStartOffset(tableIndex)).readNextUnsignedInt();
	}

	private long getFuncDataPtr(int tableIndex) throws IOException {
		// hacky, since both pcdata and funcdata are sequential int32[] arrays, just reuse logic
		// for first one to index into second one
		return getPcDataStart(npcdata + tableIndex);
	}

	/**
	 * Returns a value from the specified pc->value lookup table, for a specific 
	 * address (that should be within the function's footprint).
	 * 
	 * @param tableIndex {@link GoPcDataTable} enum
	 * @param targetPC address (inside the function) to determine the value of
	 * @return int value, will be specific to the {@link GoPcDataTable table} it comes from, or
	 * -1 if the requested table index is not present for this function
	 * @throws IOException if error reading lookup data
	 */
	public int getPcDataValue(GoPcDataTable tableIndex, long targetPC) throws IOException {
		if (tableIndex == null || tableIndex.ordinal() >= npcdata) {
			return -1;
		}
		long pcstart = getPcDataStart(tableIndex.ordinal());
		return new GoPcValueEvaluator(this, pcstart).eval(targetPC);
	}

	/**
	 * Returns all values for the specified pc->value lookup table for the entire range of the
	 * function's footprint.
	 * 
	 * @param tableIndex {@link GoPcDataTable} enum
	 * @return list of int values, will be specific to the {@link GoPcDataTable table} it comes 
	 * from, or an empty list if the requested table index is not present for this function
	 * @throws IOException if error reading lookup data
	 */
	public List<Integer> getPcDataValues(GoPcDataTable tableIndex) throws IOException {
		if (tableIndex == null || tableIndex.ordinal() >= npcdata) {
			return List.of();
		}
		long pcstart = getPcDataStart(tableIndex.ordinal());
		return new GoPcValueEvaluator(this, pcstart).evalAll(Long.MAX_VALUE);
	}

	/**
	 * Returns a value associated with this function.
	 * 
	 * @param tableIndex {@link GoFuncDataTable} enum
	 * @return requested value, or -1 if the requested table index is not present for this function
	 * @throws IOException if error reading lookup data
	 */
	public long getFuncDataValue(GoFuncDataTable tableIndex) throws IOException {
		if (tableIndex == null || tableIndex.ordinal() < 0 || tableIndex.ordinal() >= nfuncdata) {
			return -1;
		}
		long gofuncoffset = getModuledata().getGofunc();
		if (gofuncoffset == 0) {
			return -1;
		}
		long off = getFuncDataPtr(tableIndex.ordinal());
		return off == -1 ? null : gofuncoffset + off;
	}

	/**
	 * Attempts to build a 'function signature' string representing the known information about
	 * this function's arguments, using go's built-in stack trace metadata.
	 * <p>
	 * The information that can be recovered about arguments is limited to:
	 * <ul>
	 * 	<li>the size of the argument</li>
	 * 	<li>general grouping (eg. grouping of arg values as a structure or array)</li>
	 * </ul>
	 * Return value information is unknown and always represented as an "undefined" data type.
	 * 
	 * @return pseudo-function signature string, such as "undefined foo( 8, 8 )" which would
	 * indicate the function had 2 8-byte arguments 
	 * @throws IOException if error reading lookup data
	 */
	public String recoverFunctionSignature() throws IOException {
		RecoveredSignature sig = RecoveredSignature.read(this, programContext);
		return sig.toString();
	}

	/**
	 * Returns the address of this function's name string.
	 * <p>
	 * Referenced from nameoff's markup annotation
	 * 
	 * @return {@link Address}
	 */
	public Address getNameAddress() {
		GoModuledata moduledata = getModuledata();
		if (moduledata != null) {
			GoSlice slice = moduledata.getFuncnametab();
			if (slice == null) {
				slice = moduledata.getPclntable();
			}
			return slice.getArrayAddress().add(nameoff);
		}
		return null;
	}

	/**
	 * Returns the name of this function.
	 * 
	 * @return String name of this function
	 */
	public String getName() {
		GoModuledata moduledata = getModuledata();
		if (moduledata != null) {
			try {
				GoSlice slice = moduledata.getFuncnametab();
				if (slice == null) {
					slice = moduledata.getPclntable();
				}
				return slice.getElementReader(1, (int) nameoff).readNextUtf8String();
			}
			catch (IOException e) {
				// fall thru
			}
		}
		return "unknown_func_%x_%s".formatted(context.getStructureStart(),
			funcAddress != null ? funcAddress : "missing_addr");
	}

	/**
	 * Returns the name of this function, as a parsed symbol object.
	 * 
	 * @return {@link GoSymbolName} containing this function's name
	 */
	public GoSymbolName getSymbolName() {
		return GoSymbolName.parse(getName());
	}

	/**
	 * Returns a descriptive string.
	 * <p>
	 * Referenced from the entry, entryoff field's markup annotation
	 * 
	 * @return String description 
	 */
	public String getDescription() {
		return getName() + "@" + getFuncAddress();
	}

	/**
	 * Returns true if this function is inline
	 * @return true if this function is inline
	 */
	public boolean isInline() {
		return entryoff == -1 || entryoff == NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG;
	}

	/**
	 * Returns the func flags for this function.
	 * 
	 * @return {@link GoFuncFlag}s
	 */
	public Set<GoFuncFlag> getFlags() {
		return GoFuncFlag.parseFlags(flag);
	}

	/**
	 * Returns true if this function is an ASM function
	 * 
	 * @return true if this function is an ASM function
	 */
	public boolean isAsmFunction() {
		return GoFuncFlag.ASM.isSet(flag);
	}

	/**
	 * Returns information about the source file that this function was defined in.
	 * 
	 * @return {@link GoSourceFileInfo}, or null if no source file info present
	 * @throws IOException if error reading lookup data
	 */
	public GoSourceFileInfo getSourceFileInfo() throws IOException {
		GoModuledata moduledata = getModuledata();
		if (moduledata == null) {
			return null;
		}
		int fileno = new GoPcValueEvaluator(this, pcfile).eval(entry);
		int lineNum = new GoPcValueEvaluator(this, pcln).eval(entry);

		if (fileno < 0) {
			return null;
		}

		String fileName = getSourceFilename(fileno);
		return fileName != null ? new GoSourceFileInfo(fileName, lineNum) : null;
	}

	public void markupSourceFileInfo() {
		GoModuledata moduledata = getModuledata();
		if (moduledata == null) {
			return;
		}
		Program program = programContext.getProgram();
		SourceFileManager sfman = program.getSourceFileManager();

		try {
			GoPcValueEvaluator fileEval = new GoPcValueEvaluator(this, pcfile);
			GoPcValueEvaluator lineEval = new GoPcValueEvaluator(this, pcln);

			long startpc = entry;
			long prevFilenum = -1;
			int lineNum;
			while ((lineNum = lineEval.evalNext()) > 0) {
				int fileNum = fileEval.eval(startpc);
				if (fileNum < 0) {
					break;
				}
				fileEval.reset();

				if (fileNum != prevFilenum) {
					prevFilenum = fileNum;
					String fileName = getSourceFilename(fileNum);
					if (!GoConstants.GOLANG_AUTOGENERATED_FILENAME.equals(fileName)) {
						fileName = FSUtilities.normalizeNativePath(fileName);

						Address startAddr = programContext.getCodeAddress(startpc);
						long len = lineEval.getPC() - startpc;

						SourceFile sourceFile = new SourceFile(fileName);
						try {

							sfman.addSourceFile(sourceFile);
							sfman.addSourceMapEntry(sourceFile, lineNum, startAddr, len);
						}
						catch (AddressOverflowException | IllegalArgumentException e) {
							Msg.error(this, "Failed to add source file mapping", e);
						}
					}
				}
				startpc = lineEval.getPC();
			}
		}
		catch (LockException | IOException e) {
			Msg.error(this, "Failed to set source file info", e);
		}
	}

	private String getSourceFilename(int fileno) throws IOException {
		GoModuledata moduledata = getModuledata();
		long fileoff;
		GoSlice cutab = moduledata.getCutab();
		GoSlice filetab = moduledata.getFiletab();
		GoSlice nameSlice;
		if (cutab == null) { // when <= 1.15
			fileoff = filetab.readUIntElement(4 /*sizeof(uint32*/, fileno);
			nameSlice = moduledata.getPclntable();
		}
		else { // when >= 1.16
			fileoff = cutab.readUIntElement(4 /*sizeof(uint32)*/, (int) cuOffset + fileno);
			nameSlice = filetab;
		}
		String fileName = fileoff >= 0 // -1 == no value 
				? nameSlice.getElementReader(1, (int) fileoff).readNextUtf8String()
				: null;
		return fileName;
	}

	/**
	 * Returns a reference to the {@link GoModuledata} that contains this function.
	 * 
	 * @return {@link GoModuledata} that contains this function
	 */
	public GoModuledata getModuledata() {
		return programContext.findContainingModuleByFuncData(context.getStructureStart());
	}

	@Override
	public StructureContext<GoFuncData> getStructureContext() {
		return context;
	}

	@Override
	public String getStructureName() throws IOException {
		return getSymbolName().asString();
	}
	
	@Override
	public String getStructureNamespace() throws IOException {
		return getSymbolName().packagePath();
	}

	@Override
	public String getStructureLabel() throws IOException {
		return "%s___funcdata".formatted(getStructureName());
	}
	
	@Override
	public void additionalMarkup(MarkupSession session) throws IOException, CancelledException {
		if (npcdata > 0) {
			ArrayDataType pcdataArrayDT = new ArrayDataType(
				programContext.getGoTypes().getUint32DT(), npcdata, -1, programContext.getDTM());
			Address addr = context.getStructureAddress().add(getPcDataStartOffset(0));
			session.markupAddress(addr, pcdataArrayDT);
			session.labelAddress(addr, getStructureLabel() + "___pcdata", getStructureNamespace());
		}
		if (nfuncdata > 0) {
			ArrayDataType funcdataArrayDT = new ArrayDataType(
				programContext.getGoTypes().getUint32DT(), nfuncdata, -1, programContext.getDTM());
			Address addr = context.getStructureAddress().add(getPcDataStartOffset(npcdata));
			session.markupAddress(addr, funcdataArrayDT);
			session.labelAddress(addr, getStructureLabel() + "___array", getStructureNamespace());
		}
		Address deferreturnAddr = getDeferreturnAddress();
		if (deferreturnAddr != null) {
			GoSymbolName funcName = getSymbolName();
			session.labelAddress(deferreturnAddr, funcName.asString() + "_deferreturn",
				funcName.packagePath());
		}
	}

	//-------------------------------------------------------------------------------------------

	/**
	 * Represents approximate parameter signatures for a function.
	 * <p>
	 * Golang's exception/stack-trace metadata is mined to provide these approximate signatures,
	 * and any limitation in the information recovered is due to what golang stores.
	 * <p>
	 * Instead of data types, only the size and limited grouping of structure/array parameters
	 * is recoverable.
	 *   
	 * @param name name of the function
	 * @param args list of recovered arguments
	 * @param partial boolean flag, if true there was an argument that was marked as partial
	 * @param error boolean flag, if true there was an error reading the argument info
	 *
	 */
	record RecoveredSignature(String name, List<RecoveredArg> args,
			boolean partial, boolean error) {

		private static final int ARGINFO_ENDSEQ = 0xff;
		private static final int ARGINFO_STARTAGG = 0xfe;
		private static final int ARGINFO_ENDAGG = 0xfd;
		private static final int ARGINFO_DOTDOTDOT = 0xfc;
		private static final int ARGINFO_OFFSET_TOOLARGE = 0xfb;

		public static RecoveredSignature read(GoFuncData funcData, GoRttiMapper goBinary)
				throws IOException {
			RecoveredArg args = readArgs(funcData, goBinary);
			return new RecoveredSignature(funcData.getName(), args.subArgs, args.hasPartialFlag(),
				args.partial);
		}

		public static RecoveredArg readArgs(GoFuncData funcData, GoRttiMapper goBinary)
				throws IOException {
			long argInfoOffset = funcData.getFuncDataValue(GoFuncDataTable.FUNCDATA_ArgInfo);
			if (argInfoOffset == -1) {
				return new RecoveredArg(List.of(), 0, false);
			}
			BinaryReader argInfoReader = goBinary.getReader(argInfoOffset);
			Deque<List<RecoveredArg>> resultStack = new ArrayDeque<>();
			List<RecoveredArg> parent = null;
			List<RecoveredArg> current = new ArrayList<>();
			List<RecoveredArg> results = current;
			try {
				while (true) {
					int b = argInfoReader.readNextUnsignedByte();
					switch (b) {
						case ARGINFO_ENDSEQ:
							return new RecoveredArg(results, 0, false);
						case ARGINFO_STARTAGG:
							parent = current;
							current = new ArrayList<>();
							resultStack.addLast(current);
							break;
						case ARGINFO_ENDAGG:
							if (parent == null) {
								throw new IOException("no parent");
							}
							parent.add(new RecoveredArg(current, 0, false));
							current = parent;
							parent = resultStack.pollLast();
							break;
						case ARGINFO_DOTDOTDOT:
							current.add(new RecoveredArg(null, -1, true));
							break;
						case ARGINFO_OFFSET_TOOLARGE:
							current.add(new RecoveredArg(null, -2, true));
							break;
						default:
							// b == 'offset', but value doesn't seem to be consistently useful
							int sz = argInfoReader.readNextUnsignedByte();
							current.add(new RecoveredArg(null, sz, false));
							break;
					}
				}
			}
			catch (IOException e) {
				return new RecoveredArg(results, 0, true /* error flag */);
			}
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			if (partial) {
				sb.append("[partial] ");
			}
			if (error) {
				sb.append("[error] ");
			}

			sb.append("func ").append(name).append("(");

			for (int i = 0; i < args.size(); i++) {
				RecoveredArg arg = args.get(i);
				if (i != 0) {
					sb.append(", ");
				}
				arg.concatString(sb);
			}

			sb.append(") ???");

			return sb.toString();
		}
	}

	/**
	 * Represents the information recovered about a single argument.
	 * 
	 * @param subArgs list of components if this arg is an aggregate, otherwise null
	 * @param argSize size of this arg if it primitive
	 * @param partial boolean flag, if true this arg was marked as a "..." or "_" arg
	 *
	 */
	record RecoveredArg(List<RecoveredArg> subArgs, int argSize, boolean partial) {

		boolean hasPartialFlag() {
			if (partial) {
				return true;
			}
			if (subArgs != null) {
				for (RecoveredArg subArg : subArgs) {
					if (subArg.hasPartialFlag()) {
						return true;
					}
				}
			}
			return false;
		}

		void concatString(StringBuilder sb) {
			if (subArgs != null) {
				boolean first = true;
				sb.append("struct? {");
				for (RecoveredArg subArg : subArgs) {
					if (!first) {
						sb.append(", ");
					}
					first = false;
					subArg.concatString(sb);
				}
				sb.append("}");
			}
			else {
				sb.append(switch (argSize) {
					case -1 -> "...";
					case -2 -> "???";
					default -> Integer.toString(argSize);
				});
			}
		}
	}

	@Override
	public String toString() {
		return "GoFuncData [getFuncAddress()=%s, getSymbolName()=%s, getStructureContext()=%s]"
				.formatted(getFuncAddress(), getSymbolName(), getStructureContext());
	}

}
