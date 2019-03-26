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
package ghidra.program.database.function;

import ghidra.program.database.symbol.SymbolDB;
import ghidra.program.model.listing.LocalVariable;

public class LocalVariableDB extends VariableDB implements LocalVariable {

	LocalVariableDB(FunctionDB function, SymbolDB symbol) {
		super(function, symbol);
	}

	@Override
	public int getFirstUseOffset() {
		return symbol.getFirstUseOffset();
	}

	@Override
	public boolean setFirstUseOffset(int firstUseOffset) {
		functionMgr.lock.acquire();
		try {
			function.startUpdate();
			function.checkDeleted();
			symbol.setFirstUseOffset(firstUseOffset);
			functionMgr.functionChanged(function, 0);
		}
		finally {
			function.endUpdate();
			functionMgr.lock.release();
		}
		return true;
	}
}
