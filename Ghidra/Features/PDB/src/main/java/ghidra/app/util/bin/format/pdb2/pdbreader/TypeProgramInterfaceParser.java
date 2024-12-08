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

import java.io.IOException;

import ghidra.util.exception.CancelledException;

/**
 * Parser for detecting the appropriate {@link TypeProgramInterface} format for the
 *  filename given.  It then creates and returns the appropriate
 *  {@link TypeProgramInterface} object.
 */
public class TypeProgramInterfaceParser {

	private static final int TYPE_PROGRAM_INTERFACE_STREAM_NUMBER = 2;

	//==============================================================================================
	public static final int TI20_ID = 920924; // 0x00e0ed5c

	public static final int TI40_ID = 19950410;    // 0x01306b4a
	public static final int TI41_ID = 19951122;    // 0x01306e12
	public static final int TI42_ID = 19951204;    // 0x01360e64 not in MSFT doc: in in MFCS42.PDB
	public static final int TI50DEP_ID = 19960307; // 0x013091f3
	public static final int TI50_ID = 19961031;    // 0x013094c7
	public static final int TI70_ID = 19990903;    // 0x01310977
	public static final int TI80_ID = 20040203;    // 0x0131ca0b

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Parses information to determine the version of {@link TypeProgramInterface} to
	 *  create
	 * @param pdb {@link AbstractPdb} that owns this {@link TypeProgramInterface}
	 * @return the appropriate {@link TypeProgramInterface} or null if the stream does
	 *  not have enough information to be parsed
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error in processing components
	 * @throws CancelledException upon user cancellation
	 */
	public TypeProgramInterface parse(AbstractPdb pdb)
			throws IOException, PdbException, CancelledException {
		TypeProgramInterface typeProgramInterface;

		int versionNumberSize = TypeProgramInterface.getVersionNumberSize();
		int streamNumber = getStreamNumber();
		PdbByteReader reader =
			pdb.getReaderForStreamNumber(streamNumber, 0, versionNumberSize);
		if (reader.getLimit() < versionNumberSize) {
			return null;
		}

		int versionNumber = TypeProgramInterface.deserializeVersionNumber(reader);

		// TODO: we do not know where the line should be drawn for each of these
		//  AbstractTypeProgramInterface instantiations.  Had a TI50_ID that was not an 800
		//  instead of a 500.  Also believe that TI42_ID was seen to have 500.  Rest is guess
		//  until we can validate with real data.
		switch (versionNumber) {
			case TI20_ID:
			case TI40_ID:
			case TI41_ID:
				typeProgramInterface =
					new TypeProgramInterface200(pdb, getCategory(), streamNumber);
				break;
			case TI42_ID:
			case TI50DEP_ID:
				typeProgramInterface =
					new TypeProgramInterface500(pdb, getCategory(), streamNumber);
				break;
			case TI50_ID:
			case TI70_ID:
			case TI80_ID:
				typeProgramInterface =
					new TypeProgramInterface800(pdb, getCategory(), streamNumber);
				break;
			default:
				// See MSFT "doc" pdb.cpp OpenIpi() note regarding hack.
				// For IPI, if normal stream number exists and it is unnamed, then try to
				//  parse it, and accept it if no errors.  However, at this point, this would
				//  be considered an error here.  But we want to be careful about killing
				//  PDB parsing here for this case.  So we have added the isReasonableError()
				//  check here, which always returns true for TPI, but does special checking
				//  for IPI.  If IPI says it is not a reasonable error (version number looks like
				//  a non-version number and it is an API), then we must presume that the stream
				//  is not really an IPI stream and just return null.
				if (isReasonableError(versionNumber)) {
					throw new PdbException("Unknown TPI Version: " + versionNumber);
				}
				typeProgramInterface = null;
		}

		return typeProgramInterface;
	}

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Returns the standard stream number that contains the serialized Type Program Interface
	 * @return the standard stream number that contains the Type Program Interface
	 */
	protected int getStreamNumber() {
		return TYPE_PROGRAM_INTERFACE_STREAM_NUMBER;
	}

	/**
	 * Returns the appropriate {@link RecordCategory} needed while processing
	 *  the Type Program Interface} (vs. Item Program Interface)
	 * @return {@link RecordCategory#TYPE}
	 */
	protected RecordCategory getCategory() {
		return RecordCategory.TYPE;

	}

	/**
	 * Returns whether there is a reasonable error when searching for a version number.  For
	 *  the standard TPI case, any unrecognized version number is a reasonable error.  This
	 *  method gets overridden in IPI for the hack situation described earlier in the default
	 *  case above
	 * @param versionNumber the versionNumber being checked
	 * @return {@code true} if the error is a reasonable error
	 */
	protected boolean isReasonableError(int versionNumber) {
		return true;
	}

}
