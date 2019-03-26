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
package ghidra.app.util.bin.format.pe.cli.tables;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.bin.format.pe.cli.blobs.CliBlob;
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigMethodDef;
import ghidra.app.util.bin.format.pe.cli.methods.CliMethodDef;
import ghidra.app.util.bin.format.pe.cli.methods.CliMethodExtraSections;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumMethodAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumMethodImplAttributes;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Describes the MethodDef table. Each row represents a method in a specific class. Each row is stored one after the other grouped by class.
 * References to the MethodDef table are coded to indicate where the methods for a class start and end.
 */
public class CliTableMethodDef extends CliAbstractTable {

	public class CliMethodDefRow extends CliAbstractTableRow {
		public int RVA;
		public short ImplFlags; // MethodImplAttributes
		public short Flags; // MethodAttribute
		public int nameIndex;
		public int sigIndex;
//		public CliAbstractSig signature;
		private int paramIndex;
//		public List<CliParam> params;

		public static final int NEXT_ROW_PARAM_INIT_VALUE = -1;
		public int nextRowParamIndex = NEXT_ROW_PARAM_INIT_VALUE; // TODO: May not want to leave this public

		public CliMethodDefRow(int rva, short implFlags, short flags, int nameIndex,
				int sigIndex, int paramIndex) {
			this.RVA = rva;
			this.ImplFlags = implFlags;
			this.Flags = flags;
			this.nameIndex = nameIndex;
			this.sigIndex = sigIndex;
			this.paramIndex = paramIndex;
			this.nextRowParamIndex = NEXT_ROW_PARAM_INIT_VALUE;
		}

		@Override
		public String getRepresentation() {
			String methodRep = "error retrieving method representation";
			CliBlob blob = metadataStream.getBlobStream().getBlob(sigIndex);
			try {
				CliSigMethodDef methodSig;
				methodSig = new CliSigMethodDef(blob);
				methodRep = methodSig.getRepresentation();
			}
			catch (IOException e) {
			}

			String paramsStr;
			if (this.nextRowParamIndex == NEXT_ROW_PARAM_INIT_VALUE) {
				this.nextRowParamIndex =
					metadataStream.getTable(CliTypeTable.Param).getNumRows() + 1;
			}
			if (this.nextRowParamIndex == this.paramIndex) {
				paramsStr = "";
			}
			else {
				String params[] = new String[this.nextRowParamIndex - this.paramIndex];
				for (int i = 0; i < params.length; i++) {
					params[i] = getRowRepresentationSafe(CliTypeTable.Param, paramIndex + i);
				}
				paramsStr = commaifyList(Arrays.asList(params));
			}

			return String.format("%s %s Params: %s [RVA %x] Impl: %s Attr: %s",
				metadataStream.getStringsStream().getString(nameIndex),
				methodRep, paramsStr, RVA,
				CliEnumMethodImplAttributes.dataType.getName(ImplFlags & 0xffff),
				CliEnumMethodAttributes.dataType.getName(Flags & 0xffff));
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			String methodRep = "error retrieving method representation";
			CliBlob blob = stream.getBlobStream().getBlob(sigIndex);
			try {
				CliSigMethodDef methodSig;
				methodSig = new CliSigMethodDef(blob);
				methodRep = methodSig.getRepresentation(stream);
			}
			catch (IOException e) {
			}

			String paramsStr;
			if (this.nextRowParamIndex == NEXT_ROW_PARAM_INIT_VALUE) {
				this.nextRowParamIndex = metadataStream.getTable(CliTypeTable.Param).getNumRows() + 1;
			}
			if (this.nextRowParamIndex == this.paramIndex) {
				paramsStr = "";
			}
			else {
				String params[] = new String[this.nextRowParamIndex - this.paramIndex];
				for (int i = 0; i < params.length; i++) {
					params[i] = getRowShortRepSafe(CliTypeTable.Param, paramIndex + i);
				}
				paramsStr = commaifyList(Arrays.asList(params));
			}

			return String.format("%s %s Params: %s [RVA %x] Impl: %s Attr: %s",
				stream.getStringsStream().getString(nameIndex),
				methodRep, paramsStr, RVA,
				CliEnumMethodImplAttributes.dataType.getName(ImplFlags & 0xffff),
				CliEnumMethodAttributes.dataType.getName(Flags & 0xffff));
		}
	}

	public CliTableMethodDef(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		CliMethodDefRow lastRow = null;
		for (int i = 0; i < this.numRows; i++) {
			CliMethodDefRow row =
				new CliMethodDefRow(reader.readNextInt(), reader.readNextShort(),
					reader.readNextShort(), readStringIndex(reader), readBlobIndex(reader),
					readTableIndex(reader, CliTypeTable.Param));
			rows.add(row);
			strings.add(row.nameIndex);

			if (lastRow != null) {
				lastRow.nextRowParamIndex = row.paramIndex;
			}
			lastRow = row;
		}
		reader.setPointerIndex(this.readerOffset); // TODO: why do this, also elsewhere
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException {
		int rvaZero = 0;
		for (CliAbstractTableRow methodRow : rows) {
			CliMethodDefRow method = (CliMethodDefRow) methodRow;
			if (method.RVA == 0) {
				rvaZero++;
				continue;
			} // TODO: this indicates the method is either abstract, runtime, or PInvokeImpl
			Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, method.RVA); // TODO: offset, RVA?
			// Create MethodDef at RVA
			BinaryReader reader =
				new BinaryReader(new MemoryByteProvider(program.getMemory(), addr),
					!program.getMemory().isBigEndian());
			CliMethodDef methodDef = new CliMethodDef(addr, reader);
			PeUtils.createData(program, addr, methodDef.toDataType(), log);
			// Now mark up a function
			Address startAddr = addr.add(methodDef.toDataType().getLength());
			Address endAddr = startAddr.add(methodDef.getMethodSize() - 1); // TODO: -1? AddressSetView is inclusive.
			AddressSetView funcAddrSet =
				new AddressSet(startAddr, endAddr);
			String funcName = "func_" + method.RVA;
			try {
				if (method.nameIndex != 0) {
					Address nameAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary,
						monitor, log, ntHeader, metadataStream.getStringsStream(), method.nameIndex);
					BinaryReader strReader =
						new BinaryReader(new MemoryByteProvider(program.getMemory(), nameAddr),
							!program.getMemory().isBigEndian());
					funcName = strReader.readNextAsciiString();
					funcName += "-" + method.sigIndex + "-" + method.RVA; // TODO: MethodDefs are guaranteed unique on the triple (Owning TypeDef row index, Name, Signature contents)
					if (program.getFunctionManager().getFunctionAt(startAddr) == null) {
						// TODO: Why can a function exist here already?  Different methodRow's can have the same RVA...why?
						// In this case, the params table index is the only thing different.
						program.getFunctionManager().createFunction(funcName, startAddr,
							funcAddrSet, SourceType.ANALYSIS);
					}
				}
			}
			catch (InvalidInputException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			catch (OverlappingFunctionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			// Now do extra data sections
			if (methodDef.hasMoreSections()) {
				int extraOffset = methodDef.toDataType().getLength() + methodDef.getMethodSize();
				while (extraOffset % 4 != 0) {
					extraOffset++;
				}
				reader.setPointerIndex(extraOffset);
				CliMethodExtraSections extras = new CliMethodExtraSections(reader);
				Address extraAddr = addr.add(extraOffset);
				PeUtils.createData(program, extraAddr, extras.toDataType(), log);
//				program.getBookmarkManager().setBookmark(extraAddr, BookmarkType.INFO, "ExtraSection!", name + " (RVA "+method.RVA+"_10)");
			}
//			program.getBookmarkManager().setBookmark(addr, BookmarkType.INFO, "Method!", name + " (RVA "+method.RVA+"_10)");

			// Handle the signature
			CliBlob blob = metadataStream.getBlobStream().getBlob(method.sigIndex);
			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor, log,
				ntHeader, metadataStream.getBlobStream(), method.sigIndex);
			// Create PropertySig object
			CliSigMethodDef methodSig = new CliSigMethodDef(blob);
			metadataStream.getBlobStream().updateBlob(methodSig, sigAddr, program);
//			program.getBookmarkManager().setBookmark(sigAddr, BookmarkType.INFO, "Signature!", "MethodDefSig (Offset "+method.sigIndex+")");
			Function func = program.getFunctionManager().getFunctionAt(startAddr);
			try {
				if (func != null && methodSig.getReturnType() != null)
					func.setReturnType(methodSig.getReturnType().getExecutionDataType(),
						SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				e.printStackTrace(); // TODO
			}
			// TODO: This way of adding params relies on the language knowing the calling convention, etc.
//			try {
//				int offset = 0;
//				for (DataType dt : methodSig.getParamTypes()) {
//					if (dt != null) {
//						StackParameterImpl param = new StackParameterImpl("param", dt, offset, "comment", offset, SourceType.ANALYSIS);
//						func.addParameter(param, SourceType.ANALYSIS);
//						offset += dt.getLength();
//					}
//				}
//			}
//			catch (InvalidInputException e) {
//				e.printStackTrace();
//			}
		}
		if (rvaZero > 0) {
			Msg.warn(this, rvaZero + " methods with RVA 0");
		}
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "MethodDef Row", 0);
		rowDt.add(DWORD, "RVA", null);
		rowDt.add(CliEnumMethodImplAttributes.dataType, "ImplFlags",
			"Bitmask of type MethodImplAttributes");
		rowDt.add(CliEnumMethodAttributes.dataType, "Flags", "Bitmask of type MethodAttribute");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		rowDt.add(metadataStream.getBlobIndexDataType(), "Signature", "index into Blob heap");
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.Param), "ParamList", "index into Param table");
		return rowDt;
	}

	private String commaifyList(List<?> list) {
		String commaSeparated = "";
		for (Object item : list) {
			commaSeparated += item + ", ";
		}
		if (list.size() > 0) {
			commaSeparated = commaSeparated.substring(0, commaSeparated.length() - 2);
		}
		return commaSeparated;
	}

}
