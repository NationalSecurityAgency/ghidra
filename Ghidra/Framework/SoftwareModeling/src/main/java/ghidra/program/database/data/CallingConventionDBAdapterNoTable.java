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
package ghidra.program.database.data;

import java.io.IOException;
import java.util.Set;
import java.util.function.Consumer;

import javax.help.UnsupportedOperationException;

/**
 * Adapter when no Calling Convention table exists.
 */
class CallingConventionDBAdapterNoTable extends CallingConventionDBAdapter {

	/**
	 * Gets a no-table adapter for the calling convention database table.
	 */
	CallingConventionDBAdapterNoTable() {
		// no table - do nothing
	}

	@Override
	byte getCallingConventionId(String name, Consumer<String> conventionAdded) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	String getCallingConventionName(byte id) throws IOException {
		return null;
	}

	@Override
	void invalidateCache() {
		// do nothing
	}

	@Override
	Set<String> getCallingConventionNames() throws IOException {
		return Set.of();
	}

}
