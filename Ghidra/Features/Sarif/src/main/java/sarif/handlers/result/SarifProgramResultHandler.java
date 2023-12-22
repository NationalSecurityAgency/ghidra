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
package sarif.handlers.result;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.contrastsecurity.sarif.Location;
import com.contrastsecurity.sarif.PropertyBag;
import com.contrastsecurity.sarif.Result;
import com.contrastsecurity.sarif.Run;

import ghidra.program.util.ProgramTask;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.handlers.SarifResultHandler;
import sarif.managers.ProgramSarifMgr;
import sarif.model.SarifDataFrame;
import sarif.view.SarifResultsTableProvider;

public class SarifProgramResultHandler extends SarifResultHandler  {
	
	public String getKey() {
		return "Message";
	}

	public void handle(SarifDataFrame df, Run run, Result result, Map<String, Object> map) {
		this.df = df;
		this.controller = df.getController();
		
		this.run = run;
		this.result = result;
		map.put(getKey(), result.getMessage().getText());
		List<Location> locs = result.getLocations();
		if (locs != null) {
			map.put("Locations", locs);
		}
		PropertyBag properties = result.getProperties();
		if (properties != null) {
			Map<String, Object> additionalProperties = properties.getAdditionalProperties();
			if (additionalProperties != null) {
				for (Entry<String, Object> entry : additionalProperties.entrySet()) {
					map.put(entry.getKey(), entry.getValue());
				}
			}
		}
	}
	
	@Override
	protected Object parse() {
		// UNUSED
		return null;
	}
		
	@Override
	public String getActionName() {
		return "Add To Program";
	}

	@Override
	public ProgramTask getTask(SarifResultsTableProvider provider) {
		return new CommitToProgramTask(provider);
	}
	
	private class CommitToProgramTask extends ProgramTask {

		private SarifResultsTableProvider provider;
		private ProgramSarifMgr programMgr;

		protected CommitToProgramTask(SarifResultsTableProvider provider) {
			super(provider.getController().getProgram(), "CommitToProgramTask", true, true, true);
			this.provider = provider;
			this.programMgr = provider.getController().getProgramSarifMgr();
			programMgr.addManagers();
		}
		
		protected void doRun(TaskMonitor monitor) {
			int[] selected = provider.filterTable.getTable().getSelectedRows();
			Map<String, List<Map<String, Object>>> results = new HashMap<>();
			for (int row : selected) {
				Map<String, Object> result = provider.getRow(row);
				String key = (String) result.get("RuleId");
				List<Map<String, Object>> list = results.get(key);
				if (list == null) {
					list = new ArrayList<>();
				}
				list.add(result);
				results.put(key, list);
			}
			try {
				programMgr.readResults(monitor, (SarifProgramOptions) null, results);
			} catch (IOException e) {
				throw new RuntimeException("Read failed");
			}
		}
	}

}
