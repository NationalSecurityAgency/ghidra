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

import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;

/**
 * Used for creating a wrapper for when there is not associated type to the PDB type (or if we
 * have not yet created the association).
 */
public class NoTypeApplier extends MsTypeApplier {

	/**
	 * Constructor for nested type applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractMsType} to process.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public NoTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		super(applicator, msType);
	}

	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

	@Override
	void apply() {
		// Do nothing (maybe should log something... not sure)
		// applicator.getLog().appendMsg("");
	}

}
