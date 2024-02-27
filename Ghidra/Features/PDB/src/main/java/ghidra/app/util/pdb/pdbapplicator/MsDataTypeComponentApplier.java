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

/**
 * Abstract class representing the applier for a specific PDB_ID type, distinguished as having
 *  components for an actual data type but not representing a data type in and of itself.
 */
public abstract class MsDataTypeComponentApplier extends MsTypeApplier {

	/**
	 * Constructor.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 */
	public MsDataTypeComponentApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

}
