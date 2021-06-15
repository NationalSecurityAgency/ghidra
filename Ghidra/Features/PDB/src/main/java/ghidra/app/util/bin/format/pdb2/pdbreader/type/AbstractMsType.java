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

import java.util.Objects;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This is the abstract class for PDB Data Type units.
 * <P>
 * The leaves in the {@link AbstractMsType} hierarchy generally end in one of the following,
 *  which <B>generally</B> have the differences noted here:
 *  <UL>
 *  <LI> 16MsType
 *  <UL>
 *  <LI> Uses 16-bit integers for fields such as type record numbers </LI>
 *  <LI> Uses {@link StringParseType#StringSt} </LI>
 *  </UL>
 *  <LI> StMsType (not sure what <B>ST</B> means in MSFT parlance)
 *  <UL>
 *  <LI> Uses 32-bit integers for fields such as type record numbers </LI>
 *  <LI> Uses {@link StringParseType#StringSt} </LI>
 *  </UL>
 *  <LI> MsType
 *  <UL>
 *  <LI> Uses 32-bit integers for fields such as type record numbers </LI>
 *  <LI> Uses {@link StringParseType#StringNt} </LI>
 *  </UL>
 *  </UL>
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 * <P>
 * To track back to the documented API, search the above URL for where the documentation is
 *  located as "code."  Use the value of the PDB_ID for any class derived from this class to
 *  search the API code, being careful to look for data types instead of symbol types.  (Note
 *  that "PDB_ID" is not API terminology.)  Once found, you can use the defined label to find
 *  the structure that describes the layout of the serialized data; searching for that structure
 *  name can sometimes lead to methods that output information about these structures (a buffer
 *  pointer is cast to the structure pointer, leading to the ability to interpret the fields).
 *  <P>
 *  Enjoy!!!
 */
public abstract class AbstractMsType extends AbstractParsableItem implements MsType {
	protected AbstractPdb pdb;
	protected RecordNumber recordNumber;

	// Order matters on these.
	public static enum Bind {
		PTR, ARRAY, PROC, NONE
	}

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	AbstractMsType(AbstractPdb pdb, PdbByteReader reader) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		//System.out.println(reader.dump());
	}

	AbstractMsType(AbstractPdb pdb, PdbByteReader reader, RecordNumber recordNumber) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		this.recordNumber = recordNumber;
	}

	/**
	 * If the type has a name element, returns this name; else returns an empty String.
	 *  Meant to be overloaded by derived types that have a name element.
	 * @return Name.
	 */
	@Override
	public String getName() {
		return "";
	}

	/**
	 * Returns the unique ID (PdbId) for this data type.
	 * @return Identifier for this data type.
	 */
	@Override
	public abstract int getPdbId();

	@Override
	public void emit(StringBuilder builder) {
		this.emit(builder, Bind.NONE);
	}

	/**
	 * Emits {@link String} output of this class into the provided {@link StringBuilder}.
	 * @param builder {@link StringBuilder} into which the output is created.
	 * @param bind Bind ordinal used for determining when parentheses should surround components. 
	 */
	public void emit(StringBuilder builder, Bind bind) {
		builder.append("IncompleteImpl(" + this.getClass().getSimpleName() + ")");
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		emit(builder, Bind.NONE);
		return builder.toString();
	}

	@Override
	public RecordNumber getRecordNumber() {
		return recordNumber;
	}

	public void setRecordNumber(RecordNumber recordNumber) {
		this.recordNumber = recordNumber;
	}

}
