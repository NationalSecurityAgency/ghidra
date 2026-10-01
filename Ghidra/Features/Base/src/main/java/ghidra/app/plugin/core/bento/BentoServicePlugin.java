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
package ghidra.app.plugin.core.bento;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Swing;

@PluginInfo(
	shortDescription = "Displays X/Y data",
	description = "Provides visualization/navigation across multiple axes",
	category = PluginCategoryNames.GRAPH,
	packageName = CorePluginPackage.NAME,
	status = PluginStatus.RELEASED,
	servicesRequired = {
		CodeViewerService.class,
	},
	servicesProvided = {
		BentoService.class
	})
public class BentoServicePlugin extends Plugin implements BentoService {

	protected CodeViewerService codeViewerService;

	final String title;
	protected BentoProvider defaultProvider;
	protected List<BentoProvider> transientProviders = new ArrayList<>();

	public BentoServicePlugin(PluginTool tool) {
		this(tool, "Bento View");
	}

	protected BentoServicePlugin(PluginTool tool, String title) {
		this.title = title;
		super(tool);
	}

	@Override
	protected void init() {
		codeViewerService = tool.getService(CodeViewerService.class);
		defaultProvider = new BentoProvider(getTool(), this, false);
		super.init();
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(defaultProvider);
		for (BentoProvider provider : transientProviders) {
			tool.removeComponentProvider(provider);
		}
		super.dispose();
	}

	@Override
	public BentoProvider getDefaultProvider() {
		return defaultProvider;
	}

	@Override
	public BentoProvider createProvider() {
		return Swing.runNow(() -> {
			BentoProvider p = new BentoProvider(getTool(), this, true);
			transientProviders.add(p);
			p.initViews();
			tool.showComponentProvider(p, true);
			return p;
		});
	}

	public void toggleTracking() {
		// IGNORE
	}

	public CodeViewerService getCodeViewerService() {
		return codeViewerService;
	}

}
