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
package ghidra.file.formats.android.dex.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class DebugInfoItem implements StructConverter {

	private int lineStart;
	private int lineStartLength;// in bytes
	private int parametersSize;
	private int parametersSizeLength;// in bytes
	private List<Integer> parameterNames = new ArrayList<>();
	private List<Integer> parameterNamesLengths = new ArrayList<>();
	private byte[] stateMachineOpcodes;

	public DebugInfoItem(BinaryReader reader) throws IOException {
		LEB128Info leb128 = reader.readNext(LEB128Info::unsigned);
		lineStart = leb128.asUInt32();
		lineStartLength = leb128.getLength();

		leb128 = reader.readNext(LEB128Info::unsigned);
		parametersSize = leb128.asUInt32();
		parametersSizeLength = leb128.getLength();

		for (int i = 0; i < parametersSize; ++i) {
			leb128 = reader.readNext(LEB128Info::unsigned);

			parameterNames.add(leb128.asUInt32() - 1);// uleb128p1
			parameterNamesLengths.add(leb128.getLength());
		}

		int count = DebugInfoStateMachineReader.computeLength(reader.clone());
		stateMachineOpcodes = reader.readNextByteArray(count);
	}

	/**
	 * {@return the initial value for the state machine's line register}
	 * <p>
	 * Does not represent an actual positions entry.
	 */
	public int getLineStart() {
		return lineStart;
	}

	/**
	 * {@return the number of parameter names that are encoded}
	 * <p>
	 * There should be one per method parameter, excluding an instance method's this, if any.
	 */
	public int getParametersSize() {
		return parametersSize;
	}

	/**
	 * {@return a {@link List} of String indexes of the method parameter name}
	 * <p>
	 * An encoded value of NO_INDEX indicates that no name is available for the associated 
	 * parameter. The type descriptor and signature are implied from the method descriptor and signature.
	 */
	public List<Integer> getParameterNames() {
		return parameterNames;
	}

	public byte[] getStateMachineOpcodes() {
		return stateMachineOpcodes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("debug_info_item" + "_");
		builder.append(lineStartLength + "");
		builder.append(parametersSizeLength + "");
		builder.append(parametersSize + "");
		builder.append(stateMachineOpcodes.length + "");

		Structure structure = new StructureDataType(builder.toString(), 0);

		structure.add(ULEB128, lineStartLength, "line_start", null);
		structure.add(ULEB128, parametersSizeLength, "parameters_size", null);

		for (int i = 0; i < parametersSize; ++i) {
			structure.add(ULEB128, parameterNamesLengths.get(i), "parameter_" + i, null);
			builder.append("%d".formatted(parameterNamesLengths.get(i)));
		}

		ArrayDataType stateMachineArray =
			new ArrayDataType(BYTE, stateMachineOpcodes.length, BYTE.getLength());
		structure.add(stateMachineArray, "state_machine", null);

		structure.setCategoryPath(new CategoryPath("/dex/debug_info_item"));
		try {
			structure.setName(builder.toString());
		}
		catch (Exception e) {
			// ignore
		}
		return structure;
	}
}
