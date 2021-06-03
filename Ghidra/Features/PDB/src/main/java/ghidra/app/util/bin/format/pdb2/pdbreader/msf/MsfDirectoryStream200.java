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

/**
 * This is the v200 of {@link AbstractMsfDirectoryStream}.  It is essentially no different than
 *  an {@link MsfStream}.
 * @see AbstractMsfDirectoryStream
 */
class MsfDirectoryStream200 extends AbstractMsfDirectoryStream {

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.  Sets the byte length of the Stream to -1.  This method is used when the
	 *  Stream knows/reads its length.
	 * @param msf The {@link AbstractMsf} to which the Stream belongs.
	 */
	MsfDirectoryStream200(AbstractMsf msf) {
		super(msf);
	}

}
