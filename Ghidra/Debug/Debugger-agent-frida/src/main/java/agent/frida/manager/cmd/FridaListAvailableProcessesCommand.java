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
package agent.frida.manager.cmd;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import agent.frida.frida.FridaEng;
import agent.frida.manager.FridaProcess;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListAvailableProcessesCommand
		extends AbstractFridaCommand<List<Pair<String, String>>> {

	private List<FridaProcess> processList;

	public FridaListAvailableProcessesCommand(FridaManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<Pair<String, String>> complete(FridaPendingCommand<?> pending) {
		List<Pair<String, String>> result = new ArrayList<>();
		for (FridaProcess p : processList) {
			result.add(new ImmutablePair<String,String>(Long.toString(p.getPID()), p.getName()));			
		}
		return result;
	}

	@Override
	public void invoke() {
		processList = FridaEng.enumerateProcesses(manager.getCurrentTarget());
	}

}
