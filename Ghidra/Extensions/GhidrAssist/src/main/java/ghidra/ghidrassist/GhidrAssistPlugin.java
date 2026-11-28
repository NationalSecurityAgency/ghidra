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
package ghidra.ghidrassist;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.ghidrassist.actions.ExplainFunctionAction;
import ghidra.ghidrassist.actions.ExportProjectAction;
import ghidra.ghidrassist.actions.PrepareAppleBinaryAction;
import ghidra.ghidrassist.actions.ReconstructFunctionAction;
import ghidra.ghidrassist.actions.SuggestRenamesAction;
import ghidra.ghidrassist.actions.SuggestSignatureAction;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "GhidrAssist — Claude-powered RE assistant",
	description = "Embeds a Claude-powered assistant in Ghidra: chat panel, decompiler " +
		"right-click actions (explain / rename / retype / reconstruct), and export of " +
		"the current program to a buildable C project skeleton."
)
//@formatter:on
public class GhidrAssistPlugin extends ProgramPlugin {

	private final ClaudeClient claude = new ClaudeClient();
	private GhidrAssistProvider provider;

	public GhidrAssistPlugin(PluginTool tool) {
		super(tool);
		ClaudeOptions.register(tool);
	}

	@Override
	protected void init() {
		super.init();
		provider = new GhidrAssistProvider(this);
		provider.addToTool();

		tool.addAction(new ExplainFunctionAction(this));
		tool.addAction(new SuggestRenamesAction(this));
		tool.addAction(new SuggestSignatureAction(this));
		tool.addAction(new ReconstructFunctionAction(this));
		tool.addAction(new ExportProjectAction(this));
		tool.addAction(new PrepareAppleBinaryAction(this));
	}

	@Override
	protected void dispose() {
		if (provider != null) {
			provider.dispose();
		}
		super.dispose();
	}

	public ClaudeClient claude() {
		return claude;
	}

	public ClaudeOptions options() {
		return ClaudeOptions.read(tool);
	}

	public GhidrAssistProvider getProvider() {
		return provider;
	}
}
