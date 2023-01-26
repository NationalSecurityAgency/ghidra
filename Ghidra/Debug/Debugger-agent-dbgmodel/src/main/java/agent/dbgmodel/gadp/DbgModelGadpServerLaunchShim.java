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
package agent.dbgmodel.gadp;

import org.apache.commons.lang3.exception.ExceptionUtils;

import agent.dbgmodel.gadp.DbgModelGadpServer.DbgModelRunner;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;

public class DbgModelGadpServerLaunchShim implements GhidraLaunchable {

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		try {
			new DbgModelRunner().run(args);
		}
		catch (Throwable t) {
			System.err.println(ExceptionUtils.getMessage(t));
			System.exit(1);
		}
	}

}
