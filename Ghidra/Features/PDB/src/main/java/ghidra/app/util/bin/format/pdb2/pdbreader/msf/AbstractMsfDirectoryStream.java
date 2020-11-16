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
 * An MSF has a stream containing directory information.  It is called the Directory stream, and
 *  in the older style MSF format, it was the same as a user (@link MsfStream}.  Newer versions of
 *  MSF needed a higher capacity stream
 * Class extends {@link MsfStream} and represents a more complex Stream used as the Directory Stream
 *  for the newer {@link AbstractMsf} (and PDB) format.  In the older format, a regular
 *  Stream is used as the directory Stream.
 *  <P>
 * Note: This extended Stream is not used as a user Stream--just as a higher-capacity directory
 *  Stream.
 *  <P>
 * The format of how this {@link AbstractMsfDirectoryStream} is persisted to disk is described in
 *  the main {@link AbstractMsf} documentation.
 */
abstract class AbstractMsfDirectoryStream extends MsfStream {

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.  Sets the byte length of the Stream to -1.  This method is used when the
	 *  Stream knows/reads its length.
	 * @param msf The {@link AbstractMsf} to which the Stream belongs.
	 */
	AbstractMsfDirectoryStream(AbstractMsf msf) {
		super(msf);
	}

}
