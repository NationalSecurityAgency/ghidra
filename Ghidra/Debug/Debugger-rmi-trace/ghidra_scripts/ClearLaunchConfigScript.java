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
import java.util.*;

import db.Transaction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.ProgramUserData;

public class ClearLaunchConfigScript extends GhidraScript {

	protected static final String PREFIX_DBGLAUNCH = "DBGLAUNCH_";
	protected static final String KEY_LAST = "last";

	@Override
	protected void run() throws Exception {
		ProgramUserData userData = currentProgram.getProgramUserData();
		Set<String> names = userData.getStringPropertyNames();
		List<String> toDelete = new ArrayList<>();
		for (String n : names) {
			if (n.startsWith(PREFIX_DBGLAUNCH) || n.equals(KEY_LAST)) {
				toDelete.add(n);
			}
		}
		try (Transaction tx = currentProgram.openTransaction("clear")) {
			for (String n : toDelete) {
				userData.removeStringProperty(n);
			}
		}
	}
}
