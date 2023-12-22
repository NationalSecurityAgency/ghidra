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
package sarif.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import com.contrastsecurity.sarif.Artifact;
import com.contrastsecurity.sarif.ReportingDescriptorReference;
import com.contrastsecurity.sarif.Result;
import com.contrastsecurity.sarif.Run;
import com.contrastsecurity.sarif.SarifSchema210;
import com.contrastsecurity.sarif.ToolComponent;
import com.contrastsecurity.sarif.ToolComponentReference;

import sarif.SarifController;
import sarif.handlers.SarifResultHandler;
import sarif.handlers.SarifRunHandler;
import sarif.managers.ProgramSarifMgr;

/**
 * Parse the SARIF log into easier to use root structures. And helper functions.
 * {@link SarifController} to do any additional gui interactions
 */
public class SarifDataFrame {
	private List<SarifColumnKey> columns;
	private List<Map<String, Object>> tableResults;
	private Map<String, List<Map<String, Object>>> tableResultsAsMap;
	private SarifController controller;
	private Map<String, ToolComponent> componentMap;
	private Map<String, ReportingDescriptorReference> taxaMap;
	private String sourceLanguage;
	private String compiler;

	public SarifDataFrame(SarifSchema210 sarifLog, SarifController controller, boolean parseHeaderOnly) {
		this.controller = controller;

		columns = new ArrayList<>();
		tableResults = new ArrayList<>();
		tableResultsAsMap = new HashMap<>();
		columns.add(new SarifColumnKey("Tool", true));
		columns.add(new SarifColumnKey("RuleId", true));
		columns.add(new SarifColumnKey("Address", false));
		columns.add(new SarifColumnKey("Message", false));
		columns.add(new SarifColumnKey("Kind", true));
		columns.add(new SarifColumnKey("Level", true));

		Set<SarifResultHandler> resultHandlers = controller.getSarifResultHandlers();
		for (Run run : sarifLog.getRuns()) {
			parseHeader(run);
			if (parseHeaderOnly) {
				continue;
			}
			compileComponentMap(run);
			for (String name :getComponentMap().keySet()) {
				columns.add(new SarifColumnKey(name, false));
			}
			ProgramSarifMgr programMgr = controller.getProgramSarifMgr();
			for (Entry<String, Boolean> entry : programMgr.getKeys().entrySet()) {
				columns.add(new SarifColumnKey(entry.getKey(), entry.getValue()));
			}
			for (Result result : run.getResults()) {
				compileTaxaMap(run, result);

				Map<String, Object> curTableResult = new HashMap<>();
				for (SarifResultHandler handler : resultHandlers) {
					if (handler.isEnabled()) {
						handler.handle(this, run, result, curTableResult);
					}
				}
				tableResults.add(curTableResult);
				String ruleid = (String) curTableResult.get("RuleId");
				List<Map<String, Object>> list = tableResultsAsMap.get(ruleid);
				if (list == null) {
					list = new ArrayList<>();
					tableResultsAsMap.put(ruleid, list);
				}
				list.add(curTableResult);
			}
			for (SarifRunHandler handler : controller.getSarifRunHandlers()) {
				if (handler.isEnabled()) {
					handler.handle(this, run);
				}
			}
		}
	}

	private void parseHeader(Run run) {
		Set<Artifact> artifacts = run.getArtifacts();
		if (artifacts == null) {
			return;
		}
		Iterator<Artifact> iterator = artifacts.iterator();
		while (iterator.hasNext()) {
			Artifact next = iterator.next();
			sourceLanguage = next.getSourceLanguage();
			compiler = next.getDescription().getText();
		}
	}

	private void compileComponentMap(Run run) {
		componentMap = new HashMap<>();
		Set<ToolComponent> taxonomies = run.getTaxonomies();
		if (taxonomies != null) {
			for (ToolComponent tc : taxonomies) {
				componentMap.put(tc.getName(), tc);
			}
		}
	}

	private void compileTaxaMap(Run run, Result result) {
		taxaMap = new HashMap<>();
		Set<ToolComponent> taxonomies = run.getTaxonomies();
		if (taxonomies == null) {
			return;
		}
		List<ToolComponent> view = new ArrayList<>(taxonomies);
		Set<ReportingDescriptorReference> taxa = result.getTaxa();
		if (taxa != null) {
			for (ReportingDescriptorReference ref : taxa) {
				long idx = (long) ref.getToolComponent().getIndex();
				if (idx >= 0 && idx < view.size()) {
					ToolComponent tc = view.get((int) idx);
					taxaMap.put(tc.getName(), ref);
				} else {
					ToolComponentReference tc = ref.getToolComponent();
					taxaMap.put(tc.getName(), ref);
				}
			}
		}
	}

	public List<SarifColumnKey> getColumns() {
		return columns;
	}

	public List<Map<String, Object>> getTableResults() {
		return tableResults;
	}

	public Map<String, List<Map<String, Object>>> getTableResultsAsMap() {
		return tableResultsAsMap;
	}

	public SarifController getController() {
		return controller;
	}

	public Map<String, ToolComponent> getComponentMap() {
		return componentMap;
	}

	public Map<String, ReportingDescriptorReference> getTaxa() {
		return taxaMap;
	}

	public String getSourceLanguage() {
		return sourceLanguage;
	}

	public String getCompiler() {
		return compiler;
	}
}

