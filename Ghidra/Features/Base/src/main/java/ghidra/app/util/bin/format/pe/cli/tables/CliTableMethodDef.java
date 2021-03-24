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
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.*;
import ghidra.app.util.bin.format.pe.cli.blobs.CliBlob;
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigMethodDef;
import ghidra.app.util.bin.format.pe.cli.methods.CliMethodDef;
import ghidra.app.util.bin.format.pe.cli.methods.CliMethodExtraSections;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableParam.CliParamRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableTypeDef.CliTypeDefRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableTypeRef.CliTypeRefRow;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumMethodAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumMethodImplAttributes;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
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

	private static final int CLITABLEMETHODDEF_PINVOKE_JUMP_LENGTH = 0x06;

	public class CliMethodDefRow extends CliAbstractTableRow {
		public int RVA;
		public short ImplFlags; // MethodImplAttributes
		public short Flags; // MethodAttribute
		public int nameIndex;
		public int sigIndex;
		private int paramIndex;

		private static final int NEXT_ROW_PARAM_INIT_VALUE = -1;
		private int nextRowParamIndex = NEXT_ROW_PARAM_INIT_VALUE;

		private static final int METHODIMPLATTRIBUTES_CODETYPE_IL = 0x00;
		private static final int METHODIMPLATTRIBUTES_CODETYPE_NATIVE = 0x01;
		private static final int METHODIMPLATTRIBUTES_CODETYPE_OPTIL = 0x02;
		private static final int METHODIMPLATTRIBUTES_CODETYPE_RUNTIME = 0x03;
		private static final int METHODIMPLATTRIBUTES_MANAGED_MANAGED = 0x00;
		private static final int METHODIMPLATTRIBUTES_MANAGED_UNMANAGED = 0x04;
		private static final int METHODIMPLATTRIBUTES_FORWARDREF = 0x10;
		private static final int METHODIMPLATTRIBUTES_PRESERVESIG = 0x80;
		private static final int METHODIMPLATTRIBUTES_INTERNALCALL = 0x1000;
		private static final int METHODIMPLATTRIBUTES_SYNCHRONIZED = 0x20;
		private static final int METHODIMPLATTRIBUTES_NOINLINING = 0x08;
		private static final int METHODIMPLATTRIBUTES_AGGRESSIVEINLINING = 0x1000;
		private static final int METHODIMPLATTRIBUTES_MAXMETHODIMPLVAL = 0xffff;

		private static final int METHODATTRIBUTES_MEMBERACCESS_COMPILERCONTROLLED = 0x00;
		private static final int METHODATTRIBUTES_MEMBERACCESS_PRIVATE = 0x01;
		private static final int METHODATTRIBUTES_MEMBERACCESS_FAMANDASSEM = 0x02;
		private static final int METHODATTRIBUTES_MEMBERACCESS_ASSEM = 0x03;
		private static final int METHODATTRIBUTES_MEMBERACCESS_FAMILY = 0x04;
		private static final int METHODATTRIBUTES_MEMBERACCESS_FAMORASSEM = 0x05;
		private static final int METHODATTRIBUTES_MEMBERACCESS_PUBLIC = 0x06;
		private static final int METHODATTRIBUTES_STATIC = 0x10;
		private static final int METHODATTRIBUTES_FINAL = 0x20;
		private static final int METHODATTRIBUTES_VIRTUAL = 0x40;
		private static final int METHODATTRIBUTES_HIDEBYSIG = 0x80;
		private static final int METHODATTRIBUTES_VTABLELAYOUT_REUSESLOT = 0x0000;
		private static final int METHODATTRIBUTES_VTABLELAYOUT_NEWSLOT = 0x0100;
		private static final int METHODATTRIBUTES_STRICT = 0x0200;
		private static final int METHODATTRIBUTES_ABSTRACT = 0x0400;
		private static final int METHODATTRIBUTES_SPECIALNAME = 0x0800;
		private static final int METHODATTRIBUTES_PINVOKEIMPL = 0x2000;
		private static final int METHODATTRIBUTES_UNMANAGEDEXPORT = 0x08;
		private static final int METHODATTRIBUTES_RTSPECIALNAME = 0x1000;
		private static final int METHODATTRIBUTES_HASSECURITY = 0x4000;
		private static final int METHODATTRIBUTES_REQUIRESECOBJECT = 0x8000;

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

		// Static functions have four parameters but the first is an implied
		// pointer to the object they're associated with. It's not in the
		// ParameterTable and looking for the extra parameter will walk
		// you into the parameter of another function.
		boolean isStatic() {
			return (Flags & METHODATTRIBUTES_STATIC) == METHODATTRIBUTES_STATIC;
		}

		boolean isPInvokeImpl() {
			return (Flags & METHODATTRIBUTES_PINVOKEIMPL) == METHODATTRIBUTES_PINVOKEIMPL;
		}

		boolean isNative() {
			return (ImplFlags &
				METHODIMPLATTRIBUTES_CODETYPE_NATIVE) == METHODIMPLATTRIBUTES_CODETYPE_NATIVE;
		}

		boolean isManaged() {
			return (ImplFlags &
				METHODIMPLATTRIBUTES_CODETYPE_IL) == METHODIMPLATTRIBUTES_CODETYPE_IL;
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
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {

		int methodRowIndex = 0;
		for (CliAbstractTableRow method : rows) {
			methodRowIndex++;

			CliMethodDefRow methodRow = (CliMethodDefRow) method;

			// This indicates the method is abstract, runtime, or PInvokeImpl
			if (methodRow.RVA == 0) {
				continue;
			}

			Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, methodRow.RVA);
			Address startAddr = addr;
			Address endAddr = addr;

			if (methodRow.isPInvokeImpl() && methodRow.isNative()) {
				endAddr = startAddr.add(CLITABLEMETHODDEF_PINVOKE_JUMP_LENGTH - 1);
			}
			else {
				// Create MethodDef at this RVA
				BinaryReader reader =
					new BinaryReader(new MemoryByteProvider(program.getMemory(), addr),
						!program.getMemory().isBigEndian());
				CliMethodDef methodDef = new CliMethodDef(addr, reader);

				DataType methodDefDataType = methodDef.toDataType();
				PeUtils.createData(program, addr, methodDefDataType, log);

				// Get the function's address space, default to zero-length just in case
				startAddr = addr.add(methodDefDataType.getLength());
				endAddr = startAddr;
				if (methodDef.getMethodSize() > 0) {
					endAddr = startAddr.add(methodDef.getMethodSize() - 1);
				}

				// Do extra data sections in MethodDef
				if (methodDef.hasMoreSections()) {
					int extraSectionOffset =
						methodDefDataType.getLength() + methodDef.getMethodSize();

					// Round up to the next offset divisible by 4
					extraSectionOffset = ((extraSectionOffset + 3) / 4) * 4;

					reader.setPointerIndex(extraSectionOffset);
					CliMethodExtraSections extraSections = new CliMethodExtraSections(reader);
					Address extraSectionAddr = addr.add(extraSectionOffset);
					PeUtils.createData(program, extraSectionAddr, extraSections.toDataType(), log);
				}
			}

			AddressSetView funcAddrSet = new AddressSet(startAddr, endAddr);

			// Let Ghidra assign a default function name and then try to decode the
			// real one if it exists
			String funcName = null;
			if (methodRow.nameIndex > 0) {
				funcName = SymbolUtilities.replaceInvalidChars(
					metadataStream.getStringsStream().getString(methodRow.nameIndex), true);
			}

			// Get the function signature blob
			CliBlob blob = metadataStream.getBlobStream().getBlob(methodRow.sigIndex);
			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), methodRow.sigIndex);

			// Get the return type from the function signature
			CliSigMethodDef methodSig = new CliSigMethodDef(blob);
			metadataStream.getBlobStream().updateBlob(methodSig, sigAddr, program);
			DataType returnType = methodSig.getReturnType().getExecutionDataType();

			int maxSequence = 0;
			int stackOffset = 0;
			CliParam paramTypes[] = methodSig.getParamTypes();
			int paramCount = paramTypes.length;
			CliTableParam paramTable = (CliTableParam) metadataStream.getTable(CliTypeTable.Param);

			// Store the parameters in a Hashtable because by the time processing
			// finishes the number of actual parameters might change
			HashMap<Integer, ParameterImpl> parameterList = new HashMap<Integer, ParameterImpl>();

			// Some Static function first parameters being pointers to a ValueType
			// have the same number of parameters specified, but one or more are implied
			// pointers to the object they're associated with. It's not in the Parameter
			// Table and looking for the extra parameter in the table will walk you
			// into the parameter list of another function.
			ParameterImpl staticParameter = null;
			if (methodRow.isStatic() && paramCount > 0) {
				CliParam staticParam = paramTypes[0];
				String paramName = "";

				// Walk the path from the ELEMENT_TYPE_PTR to the ELEMENT_TYPE_VALUETYPE
				if (staticParam.getType() instanceof CliTypePtr) {
					CliTypePtr ptrToValueType = (CliTypePtr) staticParam.getType();
					if (ptrToValueType.getType() instanceof CliTypeValueType) {
						CliTypeValueType valueType = (CliTypeValueType) ptrToValueType.getType();

						// Get the table and row specifying the type name
						CliTypeTable tableType = valueType.getTable();
						int rowIndex = valueType.getRowIndex();

						int paramNameStringIndex = 0;
						CliAbstractTable table = metadataStream.getTable(tableType);
						CliAbstractTableRow row = table.getRow(rowIndex);
						if (tableType.id() == tableType.TypeDef.id()) {
							CliTypeDefRow typeDefRow = (CliTypeDefRow) row;
							paramNameStringIndex = typeDefRow.typeNameIndex;
						}
						else if (tableType.id() == tableType.TypeRef.id()) {
							CliTypeRefRow typeRefRow = (CliTypeRefRow) row;
							paramNameStringIndex = typeRefRow.typeNameIndex;
						}

						if (paramNameStringIndex > 0) {
							paramName =
								metadataStream.getStringsStream().getString(paramNameStringIndex);
							paramName = SymbolUtilities.replaceInvalidChars(paramName, true);

							DataType dataType = staticParam.getExecutionDataType();

							try {
								staticParameter =
									new ParameterImpl(paramName, dataType, stackOffset, program);
							}
							catch (InvalidInputException e) {
								Msg.warn(this, "Error processing parameter \"" + paramName +
									"\" in function \"" + funcName + "\": " + e.getMessage());
							}

							stackOffset += dataType.getLength();

							paramCount--;
						}
					}
				}
			}

			// Pull apart the function's Param table entries
			for (int i = 0; i < paramCount; i++) {
				CliParamRow paramRow = (CliParamRow) paramTable.getRow(methodRow.paramIndex + i);

				if (paramRow.sequence > maxSequence) {
					maxSequence = paramRow.sequence;
				}

				String paramName = SymbolUtilities.replaceInvalidChars(
					metadataStream.getStringsStream().getString(paramRow.nameIndex), true);

				DataType dataType = paramTypes[i].getExecutionDataType();

				if (paramRow.sequence == 0) {
					// Parameters with a 0 sequence number are the return type,
					// reduce the size of the array and put any previously discovered
					// parameters into it
					returnType = dataType;
				}
				else {
					// Parameters are placed in the proper order based on the sequence
					// field (1-based) to compensate for some static methods having an implied
					// first parameter that won't be represented in the Parameter Table
					// and some return types that are represented as parameters.
					try {
						parameterList.put((int) paramRow.sequence,
							new ParameterImpl(paramName, dataType, stackOffset, program));
					}
					catch (InvalidInputException e) {
						Msg.warn(this, "Error processing parameter \"" + paramName +
							"\" in function \"" + funcName + "\": " + e.getMessage());
					}

					stackOffset += dataType.getLength();
				}
			}

			ParameterImpl[] parameters = new ParameterImpl[maxSequence];
			parameterList.forEach((key, value) ->
			// Sequences are 1-based
			parameters[key - 1] = value);

			// For static functions, fill in the pointer to ValueType
			// parameters that are implied before the actual parameters
			if (methodRow.isStatic()) {
				if (staticParameter != null) {
					for (int i = 0; i < parameters.length; i++) {
						if (parameters[i] == null) {
							ParameterImpl param = null;
							try {
								param = new ParameterImpl(staticParameter.getName() + i,
									staticParameter.getDataType(), staticParameter.getStackOffset(),
									staticParameter.getProgram());
							}
							catch (InvalidInputException e1) {
								Msg.warn(this,
									"Couldn't clone " + staticParameter.getName() +
										" implied static function parameter in function : " +
										funcName + "in position " + i);
							}
							parameters[i] = param;
						}
					}
				}
			}

			try {
				Function newFunc = program.getFunctionManager()
						.createFunction(funcName, startAddr, funcAddrSet, SourceType.ANALYSIS);
				newFunc.setReturnType(returnType, SourceType.ANALYSIS);
				newFunc.updateFunction(null, null, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
					true, SourceType.ANALYSIS, parameters);
			}
			catch (NullPointerException e) {
				Msg.warn(this, "Error processing function \"" + funcName + "\" (" + methodRowIndex +
					"): Bad parameters provided");
			}
			catch (InvalidInputException e) {
				Msg.warn(this, "Error processing function \" (\" + methodRowIndex + \")" +
					funcName + "\": Invalid function");
			}
			catch (OverlappingFunctionException e) {
				String err = "Error processing function \" (\" + methodRowIndex + \")" + funcName +
					"\": Overlapping function (" + startAddr + ", " + endAddr + ": ";

				Function existingFuncA = program.getFunctionManager().getFunctionAt(startAddr);
				Function existingFuncB = program.getFunctionManager().getFunctionAt(endAddr);

				if (existingFuncA != null && existingFuncB == null) {
					err = err + existingFuncA.getName();
				}
				else if (existingFuncA == null && existingFuncB != null) {
					err = err + existingFuncB.getName();
				}
				else if (existingFuncA != null && existingFuncA == existingFuncB) {
					err = err + existingFuncA.getName();
				}

				err = err + ")";

				Msg.warn(this, err);
			}
			catch (DuplicateNameException e) {
				String paramNames = "";
				for (int i = 0; i < parameters.length - 1; i++) {
					paramNames += parameters[i].getName() + ", ";
				}
				paramNames += parameters[parameters.length - 1].getName();
				Msg.warn(this, "Error processing function \"" + funcName + "\" (" + methodRowIndex +
					"): Duplicate parameter name (" + paramNames + ")");
			}
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
