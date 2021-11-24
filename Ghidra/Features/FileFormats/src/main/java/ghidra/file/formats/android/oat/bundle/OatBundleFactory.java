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
package ghidra.file.formats.android.oat.bundle;

import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.oat.OatHeader;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class OatBundleFactory {

	public static OatBundle getOatBundle(Program oatProgram, OatHeader oatHeader,
			TaskMonitor monitor, MessageLog log) {

		// OAT program is required to fully load the bundle.
		// If program is null, then create an empty bundle.
		if (oatProgram == null) {
			return new EmptyOatBundle(oatHeader);
		}
		return new FullOatBundle(oatProgram, oatHeader, monitor, log);
	}
}
