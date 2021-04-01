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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * Function attributes used on functions within specific PDB data type.
 */
public class FunctionMsAttributes extends AbstractParsableItem {

	private static final String HAS_CPP_STYLE_RETURN_UDT_STRING = "return UDT (C++ style)";
	private static final String INSTANCE_CONSTRUCTOR_STRING = "instance constructor";
	private static final String INSTANCE_CONSTRUCTOR_VIRTUAL_BASE_STRING =
		"instance constructor of a class with virtual base";

	private boolean hasCPPStyleReturnUDT;
	private boolean isInstanceConstructor;
	private boolean isInstanceConstructorOfClassWithVirtualBases;

	/**
	 * Constructor for FunctionMsAttributes.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public FunctionMsAttributes(PdbByteReader reader) throws PdbException {
		int attributes = reader.parseUnsignedByteVal();
		processAttributes(attributes);
	}

	@Override
	public void emit(StringBuilder builder) {
		DelimiterState ds = new DelimiterState("", "|");
		builder.append(ds.out(hasCPPStyleReturnUDT, HAS_CPP_STYLE_RETURN_UDT_STRING));
		builder.append(ds.out(isInstanceConstructor, INSTANCE_CONSTRUCTOR_STRING));
		builder.append(ds.out(isInstanceConstructorOfClassWithVirtualBases,
			INSTANCE_CONSTRUCTOR_VIRTUAL_BASE_STRING));
	}

	private void processAttributes(int attributes) {
		hasCPPStyleReturnUDT = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		isInstanceConstructor = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		isInstanceConstructorOfClassWithVirtualBases = ((attributes & 0x0001) == 0x0001);
	}

	boolean isConstructor() {
		return isInstanceConstructor || isInstanceConstructorOfClassWithVirtualBases;
	}

}
