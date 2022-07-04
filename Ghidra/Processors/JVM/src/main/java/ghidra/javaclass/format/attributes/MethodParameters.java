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
package ghidra.javaclass.format.attributes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * This class stores information about a single method parameter
 */
public class MethodParameters implements StructConverter {

	private final static int ACC_FINAL_INDEX = 0x10;
	private final static int ACC_SYNTHETIC_INDEX = 0x1000;
	private final static int ACC_MANDATED_INDEX = 0x8000;

	private int name_index;
	private int access_flags;

	/**
	 * Creates a new {@code MethodParameters} object from the current index of {@code reader}
	 * and advances the index.
	 * @param reader source of bytes
	 * @throws IOException thrown if problem reading bytes
	 */
	public MethodParameters(BinaryReader reader) throws IOException {
		name_index = Short.toUnsignedInt(reader.readNextShort());
		access_flags = Short.toUnsignedInt(reader.readNextShort());
	}

	/**
	 * Returns the name index.  If the index is 0, then this formal parameter
	 * does not have a name.  Otherwise, the constant pool entry at the index
	 * is a {@code CONSTANT_Utf8_Info} structure encoding the name of the
	 * parameter.
	 * @return index or 0
	 */
	public int getNameIndex() {
		return name_index;
	}

	/**
	 * Returns a integer whose bits are treated as flags to encode various properties
	 * of the parameter
	 * @return access flags
	 */
	public int getAcccessFlags() {
		return access_flags;
	}

	/**
	 * Returns a {@code boolean} representing whether or not the parameter was declared
	 * {@code final}
	 * @return true if final
	 */
	public boolean isFinal() {
		return (access_flags & ACC_FINAL_INDEX) != 0;
	}

	/**
	 * Returns a {@code boolean} representing whether or not the parameter is synthetic, i.e.,
	 * a compiler artifact rather than being explicitly or implicitly declared in the source.
	 * @return true if synthetic
	 */
	public boolean isSynthetic() {
		return (access_flags & ACC_SYNTHETIC_INDEX) != 0;
	}

	/**
	 * Returns a {@code boolean} representing whether or not the parameter is mandated, i.e.,
	 * implicitly declared in source code and forced to be emitted by all compilers.
	 * @return true if synthetic
	 */
	public boolean isMandated() {
		return (access_flags & ACC_MANDATED_INDEX) != 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = new StructureDataType("method_parameters", 0);
		structure.add(WORD, "name_index", null);
		structure.add(WORD, "access_flags", null);
		return structure;
	}

}
