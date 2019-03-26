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
package ghidra.app.util.bin.format.pe.cli.blobs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.program.model.data.*;
import ghidra.util.exception.InvalidInputException;

public class CliSigMethodDef extends CliAbstractSig {
	
	private CliRetType retType;
	private CliParam params[];
	private int sizeOfCount;
	private int genericParamCount;
	private int sizeOfGenericCount;
	
	public CliSigMethodDef(CliBlob blob) throws IOException {
		super(blob);

		// Now read our special stuff.
		BinaryReader reader = getContentsReader();
		byte firstByte = reader.readNextByte();
		// firstByte is HASTHIS | EXPLICITTHIS | DEFAULT | VARARG | GENERIC
		if ((firstByte & 0x10) == 0x10) { // GENERIC
			long origIndex = reader.getPointerIndex();
			genericParamCount = decodeCompressedUnsignedInt(reader);
			sizeOfGenericCount = (int) (reader.getPointerIndex() - origIndex);
		}
		long origIndex = reader.getPointerIndex();
		int paramCount = decodeCompressedUnsignedInt(reader);
		this.sizeOfCount = (int) (reader.getPointerIndex() - origIndex);
		try {
			retType = new CliRetType(reader);
		}
		catch (InvalidInputException e) {
			retType = null;
		}
		params = new CliParam[paramCount];
		for (int i = 0; i < paramCount; i++) {
			try {
				params[i] = new CliParam(reader);
			}
			catch (InvalidInputException e) { /* Do not add to params() */ }
		}
	}

	@Override
	public String getContentsName() {
		return "MethodDefSig";
	}
	
	@Override
	public String getContentsComment() {
		return "Type info for method return and params";
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(BYTE, "FirstByte", "ORed calling convention and THIS presence"); // TODO: enum
		if (genericParamCount > 0) {
			struct.add(getDataTypeForBytes(sizeOfGenericCount), "GenParamCount",
					"Number of generic paramameters for the method");
		}
		struct.add(getDataTypeForBytes(sizeOfCount), "Count", "Number of param types to follow RetType");
		struct.add(retType.getDefinitionDataType(), "RetType", null);
		for (CliParam param : params)
			struct.add(param.getDefinitionDataType(), null, null);
		return struct;
	}

	public CliRetType getReturnType() {
		return retType;
	}
	
	public CliParam[] getParamTypes() {
		return params.clone();
	}

	protected String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		String rep = getRepresentationOf(retType, stream, isShort);
		rep += " fn(";
		for (CliParam param : params) {
			if (param == null) 
				rep += "unidentified_param_type, ";
			else {
				rep += getRepresentationOf(param, stream, isShort) + ", ";
			}
		}
		if (params.length > 0)
			rep = rep.substring(0, rep.length()-2); // Take off last comma+space
		rep += ")";
		return rep;
	}

}
