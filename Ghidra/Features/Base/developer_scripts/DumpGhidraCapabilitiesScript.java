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

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.util.classfinder.ClassSearcher;

public class DumpGhidraCapabilitiesScript extends GhidraScript {

	private Map<String, List<PluginDescription>> pluginMap = new HashMap<>();
	private Map<String, List<Analyzer>> analyzerMap = new HashMap<>();

	@Override
	public void run() throws Exception {
		PluginConfigurationModel model = new PluginConfigurationModel(state.getTool());
		List<PluginDescription> descriptions = model.getAllPluginDescriptions();
		for (PluginDescription pluginDescription : descriptions) {
			String moduleName = pluginDescription.getModuleName();

			if (moduleName == null) {
				moduleName = "[ No Module ]";
			}

			addPlugin(moduleName, pluginDescription);
		}

		List<Analyzer> instances = ClassSearcher.getInstances(Analyzer.class);
		for (Analyzer analyzer : instances) {
			Class<? extends Analyzer> clazz = analyzer.getClass();

			ResourceFile module = Application.getModuleContainingClass(clazz.getName());

			String moduleName;
			if (module == null) {
				moduleName = "[ No Module ]";
			}
			else {
				moduleName = module.getName();
			}

			addAnalyzer(moduleName, analyzer);
		}

		Set<String> set = new HashSet<>(pluginMap.keySet());
		set.addAll(analyzerMap.keySet());
		List<String> list = new ArrayList<>(set);
		Collections.sort(list);
		System.out.println("Modules:");
		for (String module : list) {
			System.out.println("\t" + module);
			List<PluginDescription> plugins = pluginMap.get(module);
			if (plugins != null && !plugins.isEmpty()) {
				System.out.println("\t\tPlugins: ");
				Collections.sort(plugins);
				for (PluginDescription pd : plugins) {
					System.out.println("\t\t\t" + pd.getName());
					System.out.println("\t\t\t\t" + pd.getShortDescription());
					System.out.println("\t\t\t\t" + pd.getDescription());
				}
			}

			List<Analyzer> analyzers = analyzerMap.get(module);
			if (analyzers != null && !analyzers.isEmpty()) {
				System.out.println("\t\tAnalyzers: ");
				Collections.sort(analyzers,
					(arg0, arg1) -> arg0.getName().compareTo(arg1.getName()));
				for (Analyzer analyzer : analyzers) {
					System.out.println("\t\t\t" + analyzer.getName());
					System.out.println("\t\t\t\t" + analyzer.getDescription());
				}
			}
		}
	}

	private void addAnalyzer(String moduleName, Analyzer analyzer) {
		List<Analyzer> list = analyzerMap.get(moduleName);
		if (list == null) {
			list = new ArrayList<>();
			analyzerMap.put(moduleName, list);
		}
		list.add(analyzer);

	}

	private void addPlugin(String moduleName, PluginDescription pluginDescription) {
		List<PluginDescription> list = pluginMap.get(moduleName);
		if (list == null) {
			list = new ArrayList<>();
			pluginMap.put(moduleName, list);
		}
		list.add(pluginDescription);
	}
}
