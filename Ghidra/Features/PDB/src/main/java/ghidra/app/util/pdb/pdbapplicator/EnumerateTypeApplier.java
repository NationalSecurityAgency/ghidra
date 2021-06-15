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
package ghidra.app.util.pdb.pdbapplicator;

import java.math.BigInteger;

import ghidra.app.util.bin.format.pdb2.pdbreader.Numeric;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractEnumerateMsType;
import ghidra.app.util.pdb.PdbNamespaceUtils;
import ghidra.program.model.data.DataType;

/**
 * Applier for {@link AbstractEnumerateMsType} types.
 */
public class EnumerateTypeApplier extends MsTypeApplier {

	private String fieldName;
	private Numeric numeric;

	/**
	 * Constructor for enumerate type applier, for transforming a enumerate into a
	 * Ghidra DataType.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractEnumerateMsType} to process.
	 */
	public EnumerateTypeApplier(PdbApplicator applicator, AbstractEnumerateMsType msType) {
		super(applicator, msType);
	}

	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

	@Override
	void apply() {
		dataType = applyEnumerateMsType((AbstractEnumerateMsType) msType);
//		DataType dataType = applyEnumerateMsType((AbstractEnumerateMsType) msType);
//		ghDataType = dataType; // temporary while below is commented-out
		// TODO: uncomment when above method not returning null
//		ghDataTypeDB = applicator.resolve(dataType);
	}

	String getName() {
		return fieldName;
	}

	Numeric getNumeric() {
		return numeric;
	}

	private DataType applyEnumerateMsType(AbstractEnumerateMsType type) {

		//TODO: currently dropping these on the floor.  The access methods above do the same work.

		fieldName = PdbNamespaceUtils.fixUnnamed(type.getName(), index);

		// TODO: Need to build test sample with these.
		// TODO: Need to see if can do real number; need to modify Numeric for both
		//  integral and real numbers.  Possibly need to make Numeric a "type" instead
		//  of just something to read using ByteReader.
		numeric = type.getNumeric();

		return null;
	}

}
