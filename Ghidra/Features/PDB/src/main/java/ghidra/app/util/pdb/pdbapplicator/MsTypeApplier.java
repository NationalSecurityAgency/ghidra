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

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.DataType;

/**
 * Abstract class representing the applier for a specific PDB_ID type.  The
 * {@link #apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)} method
 * creates an associated {@link DataType}, if applicable,  The latter of these forces the
 * creation of the defined type when and forward reference type is not appropriate for the
 * consumer.  Note that this should only be used when sanctioned and not on a whim.  Currently,
 * such situations include when ghidra needs a defined type for the underlying type of an array,
 * when used as a base class of a class or when needed as a member of another class/composite.
 * Methods associated with the {@link MsTypeApplier} or derived class will
 * make fields available to the user, first by trying to get them from the {@link DataType},
 * otherwise getting them from the {@link AbstractMsType} argument.
 */
public abstract class MsTypeApplier {

	protected DefaultPdbApplicator applicator;

	/**
	 * Constructor.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 */
	public MsTypeApplier(DefaultPdbApplicator applicator) {
		this.applicator = applicator;
	}

	/**
	 * Puts message to {@link PdbLog} and to Msg.info()
	 * @param originator a Logger instance, "this", or YourClass.class
	 * @param message the message to display
	 */
	protected void pdbLogAndInfoMessage(Object originator, String message) {
		applicator.pdbLogAndInfoMessage(originator, message);
	}

}
