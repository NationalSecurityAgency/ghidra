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
 * An individual PDB C13 Cross-Scope Export record
 */
public class C13CrossScopeExport {
	private long localId; // unsigned 32-bit
	private long globalId; // unsigned 32-bit

	public static int getBaseRecordSize() {
		return 8;
	}

	public C13CrossScopeExport(PdbByteReader reader) throws PdbException {
		localId = reader.parseUnsignedIntVal();
		globalId = reader.parseUnsignedIntVal();
	}

	/**
	 * Returns the local ID
	 * @return the local ID
	 */
	public long getLocalId() {
		return localId;
	}

	/**
	 * Returns the global ID
	 * @return the global ID
	 */
	public long getGlobalId() {
		return globalId;
	}

	@Override
	public String toString() {
		return String.format("0x%08x, 0x%08x", localId, globalId);
	}
}
