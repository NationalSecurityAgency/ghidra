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
package ghidra.app.util.bin.format.pdb2.pdbreader;

/**
 * This class is an extension of {@link TypeProgramInterface800}, whose sole purpose
 *  is to allow for testing of internal components of {@link AbstractPdb} classes.  It is not
 *  part of the production PDB Reader.
 */
public class DummyTypeProgramInterface800 extends TypeProgramInterface800 {

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a basic object.
	 *  Note: not all values are initialized.  
	 * @param pdb The AbstractPdb foundation for the {@link TypeProgramInterface800}.
	 * @param typeIndexMin int. The IndexMin to set/use.
	 * @param typeIndexMaxExclusive int. One greater than the MaxIndex to set/use
	 */
	DummyTypeProgramInterface800(AbstractPdb pdb, int typeIndexMin, int typeIndexMaxExclusive) {
		super(pdb, RecordCategory.TYPE, -1);
		this.typeIndexMin = typeIndexMin;
		this.typeIndexMaxExclusive = typeIndexMaxExclusive;
	}

}
