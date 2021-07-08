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
package ghidra.app.util.bin.format.pdb;

import ghidra.program.model.listing.Program;

/**
 * Program Information options related to PDB data.  All option keys specified
 * by this constants file are children of the Program Information options.  Example:
 * <pre>
 *    Options options = program.getOptions({@link Program#PROGRAM_INFO});
 *    boolean isPdbLoaded = options.getBoolean({@link #PDB_LOADED}, false);
 * </pre>
 */
public class PdbParserConstants {
	/**
	 * Option key which indicates if PDB has been loaded/applied to program (Boolean).
	 */
	public final static String PDB_LOADED    = "PDB Loaded";

	/**
	 * Option key which indicates PDB filename or path as specified by loaded program (String).
	 */
	public final static String PDB_FILE      = "PDB File";

	/**
	 * Option key which indicates PDB Age as specified by loaded program (String, hex value without 0x prefix).
	 */
	public final static String PDB_AGE = "PDB Age";

	/**
	 * Option key which indicates PDB Signature as specified by loaded program (String).
	 */
	public final static String PDB_SIGNATURE = "PDB Signature";

	/**
	 * Option key which indicates PDB Version as specified by loaded program (String).
	 */
	public final static String PDB_VERSION   = "PDB Version";

	/**
	 * Option key which indicates PDB GUID as specified by loaded program (String).
	 */
	public final static String PDB_GUID      = "PDB GUID";
}
