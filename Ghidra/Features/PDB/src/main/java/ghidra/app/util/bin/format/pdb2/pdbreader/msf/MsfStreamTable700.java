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
package ghidra.app.util.bin.format.pdb2.pdbreader.msf;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader;

/**
 * This class is the version of {@link AbstractMsfStreamTable} for Microsoft v7.00 MSF.
 */
class MsfStreamTable700 extends AbstractMsfStreamTable {

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.
	 * @param msf The MSF associated for this class.
	 */
	MsfStreamTable700(AbstractMsf msf) {
		super(msf);
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	protected void parseExtraField(PdbByteReader reader) {
		// Do nothing
	}

	@Override
	protected int getMaxNumStreamsAllowed() {
		return 0x10000;
	}

}
