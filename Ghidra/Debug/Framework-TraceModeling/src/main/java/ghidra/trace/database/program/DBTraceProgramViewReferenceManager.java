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
package ghidra.trace.database.program;

import ghidra.trace.model.listing.TraceCodeOperations;
import ghidra.trace.model.symbol.TraceReferenceOperations;

public class DBTraceProgramViewReferenceManager extends AbstractDBTraceProgramViewReferenceManager {
	public DBTraceProgramViewReferenceManager(DBTraceProgramView program) {
		super(program);
	}

	@Override
	protected TraceReferenceOperations getReferenceOperations(boolean createIfAbsent) {
		return program.trace.getReferenceManager();
	}

	@Override
	protected TraceCodeOperations getCodeOperations(boolean createIfAbsent) {
		return program.trace.getCodeManager();
	}
}
