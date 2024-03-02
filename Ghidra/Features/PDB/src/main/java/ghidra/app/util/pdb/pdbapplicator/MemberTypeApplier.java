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

import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMemberMsType;

/**
 * Applier for {@link AbstractMemberMsType} types.
 */
public class MemberTypeApplier extends MsDataTypeComponentApplier {

	// Intended for: AbstractMemberMsType
	/**
	 * Constructor for member type applier
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 */
	public MemberTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

}
