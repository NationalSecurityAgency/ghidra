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
package agent.lldb.manager.cmd;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import SWIG.SBCommandReturnObject;
import SWIG.SBDebugger;
import agent.lldb.lldb.DebugClientImpl;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.util.Msg;

public class LldbListAvailableProcessesCommand
		extends AbstractLldbCommand<List<Pair<String, String>>> {

	private String output;

	public LldbListAvailableProcessesCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<Pair<String, String>> complete(LldbPendingCommand<?> pending) {
		List<Pair<String, String>> result = new ArrayList<>();
		String[] lines = output.split("\n");
		// Skip count & header
		for (int i = 3; i < lines.length; i++) {
			String[] fields = lines[i].split("\\s+");
			try {
				result.add(new ImmutablePair<String,String>(fields[0], fields[fields.length-1]));
			} catch (Exception e) {
				Msg.error(this, e.getMessage());
			}
		}
		return result;
	}

	@Override
	public void invoke() {
		DebugClientImpl client = (DebugClientImpl) manager.getClient();
		SBDebugger sbd = client.getDebugger();
		SBCommandReturnObject obj = new SBCommandReturnObject();
		sbd.GetCommandInterpreter().HandleCommand("platform process list", obj);
		output = obj.GetOutput();
	}

}
