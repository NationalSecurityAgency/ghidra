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

public class PdbParserConstants {
	public final static String PDB_LOADED    = "PDB Loaded";
	public final static String PDB_FILE      = "PDB File";
	// NOTE: PDB_AGE stored as Hex string value without 0x or other format indicator
	public final static String PDB_AGE       = "PDB Age"; 
	public final static String PDB_SIGNATURE = "PDB Signature";
	public final static String PDB_VERSION   = "PDB Version";
	public final static String PDB_GUID      = "PDB GUID";
}
