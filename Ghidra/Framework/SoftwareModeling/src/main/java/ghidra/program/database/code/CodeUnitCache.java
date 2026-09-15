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
package ghidra.program.database.code;

import db.DBRecord;
import ghidra.program.database.DbCache;
import ghidra.program.database.code.CodeManager.CodeUnitFactory;
import ghidra.util.Lock;

/**
 * Specialized version of {@link DbCache} for code units. Because the cache has to 
 * deal with both instructions and data, it is more convenient to have methods to specifically
 * get instruction or data when the client knows which it expects.
 */
public class CodeUnitCache extends DbCache<CodeUnitDB> {

	public CodeUnitCache(CodeUnitFactory factory, Lock lock, int hardCacheSize) {
		super(factory, lock, hardCacheSize);
	}

	/**
	 * Gets the Data object for the given record or null if the record is an instruction record.
	 * @param dbRecord the data or instruction record
	 * @return the DataDB for the record or null if the record is an instruction
	 */
	public DataDB getData(DBRecord dbRecord) {
		CodeUnitDB cu = getCachedInstance(dbRecord);
		if (cu instanceof DataDB data) {
			return data;
		}
		return null;
	}

	/**
	 * Gets the Instruction object for the given record or null if the record is a data record.
	 * @param dbRecord the data or instruction record
	 * @return the InstructionDB for the record or null if the record is a Data record
	 */
	public InstructionDB getInstruction(DBRecord dbRecord) {
		CodeUnitDB cu = getCachedInstance(dbRecord);
		if (cu instanceof InstructionDB instruction) {
			return instruction;
		}
		return null;
	}
}
