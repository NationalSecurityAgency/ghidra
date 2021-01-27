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
import ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliParam;
import ghidra.app.util.bin.format.pe.cli.blobs.CliBlob;
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigMethodDef;
import ghidra.app.util.bin.format.pe.cli.methods.CliMethodDef;
import ghidra.app.util.bin.format.pe.cli.methods.CliMethodExtraSections;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableParam.CliParamRow;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumMethodAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumMethodImplAttributes;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
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
		private int paramIndex;

		private static final int NEXT_ROW_PARAM_INIT_VALUE = -1;
		private int nextRowParamIndex = NEXT_ROW_PARAM_INIT_VALUE;

		public CliMethodDefRow(int rva, short implFlags, short flags, int nameIndex, int sigIndex,
				int paramIndex) {
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
				metadataStream.getStringsStream().getString(nameIndex), methodRep, paramsStr, RVA,
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
				this.nextRowParamIndex =
					metadataStream.getTable(CliTypeTable.Param).getNumRows() + 1;
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
				stream.getStringsStream().getString(nameIndex), methodRep, paramsStr, RVA,
				CliEnumMethodImplAttributes.dataType.getName(ImplFlags & 0xffff),
				CliEnumMethodAttributes.dataType.getName(Flags & 0xffff));
		}
	}

	public CliTableMethodDef(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		CliMethodDefRow lastRow = null;
		for (int i = 0; i < this.numRows; i++) {
			CliMethodDefRow row = new CliMethodDefRow(reader.readNextInt(), reader.readNextShort(),
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
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {

		int rvaZero = 0;

		for (CliAbstractTableRow method : rows) {
			CliMethodDefRow methodRow = (CliMethodDefRow) method;

			// This indicates the method is abstract, runtime, or PInvokeImpl
			if (methodRow.RVA == 0) {
				rvaZero++;
				continue;
			}

			Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, methodRow.RVA);

			// Create MethodDef at this RVA
			BinaryReader reader =
				new BinaryReader(new MemoryByteProvider(program.getMemory(), addr),
					!program.getMemory().isBigEndian());
			CliMethodDef methodDef = new CliMethodDef(addr, reader);

			PeUtils.createData(program, addr, methodDef.toDataType(), log);

			// Get the function's address space, default to zero-length just in case
			Address startAddr = addr.add(methodDef.toDataType().getLength());
			Address endAddr = startAddr;
			if (methodDef.getMethodSize() > 0) {
				endAddr = startAddr.add(methodDef.getMethodSize() - 1);
			}
			AddressSetView funcAddrSet = new AddressSet(startAddr, endAddr);

			// Let Ghidra assign a default function name and then try to decode the
			// real one if it exists
			String funcName = null;
			if (methodRow.nameIndex > 0) {
				funcName = metadataStream.getStringsStream().getString(methodRow.nameIndex);
			}

			// Do extra data sections in MethodDef
			if (methodDef.hasMoreSections()) {
				int extraSectionOffset =
					methodDef.toDataType().getLength() + methodDef.getMethodSize();

				// Round up to the next offset divisible by 4
				extraSectionOffset = ((extraSectionOffset + 3) / 4) * 4;

				reader.setPointerIndex(extraSectionOffset);
				CliMethodExtraSections extraSections = new CliMethodExtraSections(reader);
				Address extraSectionAddr = addr.add(extraSectionOffset);
				PeUtils.createData(program, extraSectionAddr, extraSections.toDataType(), log);
			}

			// Get the function signature blob
			CliBlob blob = metadataStream.getBlobStream().getBlob(methodRow.sigIndex);
			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), methodRow.sigIndex);

			// Get the return type from the function signature
			CliSigMethodDef methodSig = new CliSigMethodDef(blob);
			metadataStream.getBlobStream().updateBlob(methodSig, sigAddr, program);
			DataType returnType = methodSig.getReturnType().getExecutionDataType();

			// Pull apart the function parameter names and types
			int stackOffset = 0;
			CliParam paramTypes[] = methodSig.getParamTypes();
			CliTableParam paramTable = (CliTableParam) metadataStream.getTable(CliTypeTable.Param);
			ParameterImpl parameters[] = new ParameterImpl[paramTypes.length];

			for (int i = 0; i < paramTypes.length; i++) {
				CliParamRow paramRow = (CliParamRow) paramTable.getRow(methodRow.paramIndex + i);

				String paramName = metadataStream.getStringsStream().getString(paramRow.nameIndex);
				DataType dataType = paramTypes[i].getExecutionDataType();

				try {
					parameters[i] = new ParameterImpl(paramName, dataType, stackOffset, program);
				}
				catch (InvalidInputException e) {
					Msg.warn(this, "Error processing parameter \"" + paramName +
						"\" in function \"" + funcName + "\": " + e.getMessage());
				}

				stackOffset += dataType.getLength();
			}

			try {
				Function newFunc = program.getFunctionManager()
						.createFunction(funcName, startAddr, funcAddrSet, SourceType.ANALYSIS);
				newFunc.setReturnType(returnType, SourceType.ANALYSIS);
				newFunc.updateFunction(null, null, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
					true, SourceType.ANALYSIS, parameters);
			}
			catch (InvalidInputException e) {
				Msg.warn(this, "Error processing function \"" + funcName + "\"");
			}
			catch (OverlappingFunctionException e) {
				Msg.warn(this, "Error processing function \"" + funcName + "\"");
			}
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
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.Param), "ParamList",
			"index into Param table");
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
