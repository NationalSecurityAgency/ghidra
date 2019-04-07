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

public class CliSigProperty extends CliAbstractSig {
	private int sizeOfCount;
	private CliRetType returnType;
	private CliParam params[];
	
	public CliSigProperty(CliBlob blob) throws IOException {
		super(blob);

		// Now read our special data from the blob!
		BinaryReader reader = getContentsReader();
		byte firstByte = reader.readNextByte();
		if ((firstByte & 0x08) != 0x08)
			return; // Do something worse than just return?
		long origIndex = reader.getPointerIndex();
		int paramsCount = decodeCompressedUnsignedInt(reader);
		this.sizeOfCount = (int) (reader.getPointerIndex() - origIndex);
		try {
			returnType = new CliRetType(reader);
		}
		catch (InvalidInputException e) {
			returnType = null;
		}
		params = new CliParam[paramsCount];
		for (int i = 0; i < paramsCount; i++) {
			try {
				params[i] = new CliParam(reader);
			}
			catch (InvalidInputException e) {
				params[i] = null;
				e.printStackTrace();
			}
		}
	}
	
	@Override
	public String getContentsName() {
		return "PropertySig";
	}
	
	@Override
	public String getContentsComment() {
		return "Contains signature for properties. Gives params for getters/setters.";
	}
	
	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(BYTE, "PROPERTY", "must be 0x08 or 0x28. ORed 0x20=HASTHIS and 0x08=PROPERTY");
		struct.add(getDataTypeForBytes(sizeOfCount), "Count", "Number of params to follow RetType");
		struct.add(returnType.getDefinitionDataType(), "RetType", "Return type");
		for (CliParam param : params)
			struct.add(param.getDefinitionDataType(), "Param", null);
		return struct;
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		String paramsStr = "";
		for (CliParam param : params) {
			paramsStr += getRepresentationOf(param, stream, isShort) + ", ";
		}
		if (params.length > 0)
			paramsStr = paramsStr.substring(0, paramsStr.length() - 2); // remove comma+space
		return String.format("%s get(%s)", getRepresentationOf(returnType, stream, isShort), paramsStr);  
	}
	
}
