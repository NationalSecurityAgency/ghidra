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

import ghidra.app.util.bin.format.pdb2.pdbreader.Numeric;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractEnumerateMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.pdb.PdbNamespaceUtils;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractEnumerateMsType} types.
 */
public class EnumerateTypeApplier extends MsTypeApplier {

	// Intended for: AbstractEnumerateMsType
	/**
	 * Constructor for enumerate type applier, for transforming a enumerate into a
	 * Ghidra DataType.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 */
	public EnumerateTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	@Override
	DataType apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		DataType dataType = applyEnumerateMsType((AbstractEnumerateMsType) type);
		//dataType is null for now... so no resolve
		//return applicator.resolve(dataType);
		return null;
	}

	String getName(AbstractEnumerateMsType type) {
		return PdbNamespaceUtils.fixUnnamed(type.getName(), type.getRecordNumber().getNumber());
	}

	Numeric getNumeric(AbstractEnumerateMsType type) {
		return type.getNumeric();
	}

	private DataType applyEnumerateMsType(AbstractEnumerateMsType type) {

		//TODO: currently dropping these on the floor.  The access methods above do the same work.

		String fieldName =
			PdbNamespaceUtils.fixUnnamed(type.getName(), type.getRecordNumber().getNumber());

		// TODO: Need to build test sample with these.
		// TODO: Need to see if can do real number; need to modify Numeric for both
		//  integral and real numbers.  Possibly need to make Numeric a "type" instead
		//  of just something to read using ByteReader.
		Numeric numeric = type.getNumeric();

		return null;
	}

}
