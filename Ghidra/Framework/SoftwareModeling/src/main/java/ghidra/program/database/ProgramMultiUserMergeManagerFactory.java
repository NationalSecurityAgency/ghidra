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
package ghidra.program.database;

import ghidra.framework.PluggableServiceRegistry;
import ghidra.framework.data.DomainObjectMergeManager;
import ghidra.program.model.listing.Program;

public class ProgramMultiUserMergeManagerFactory {
	static {
		PluggableServiceRegistry.registerPluggableService(
			ProgramMultiUserMergeManagerFactory.class, new ProgramMultiUserMergeManagerFactory());
	}

	public static DomainObjectMergeManager getMergeManager(Program resultsObj,
			Program sourceObj, Program originalObj, Program latestObj) {
		ProgramMultiUserMergeManagerFactory factory =
			PluggableServiceRegistry.getPluggableService(ProgramMultiUserMergeManagerFactory.class);
		return factory.doGetMergeManager(resultsObj, sourceObj, originalObj, latestObj);
	}

	protected DomainObjectMergeManager doGetMergeManager(Program resultsObj,
			Program sourceObj, Program originalObj, Program latestObj) {
		return null;
	}
}
