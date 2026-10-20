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
package ghidra.app.plugin.core.assembler;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections4.map.DefaultedMap;
import org.apache.commons.collections4.map.LazyMap;

import docking.ActionContext;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;
import ghidra.util.task.CachingSwingWorker;
import ghidra.util.task.TaskMonitor;

/**
 * A plugin for assembly
 * 
 * <p>
 * This plugin currently provides two actions: {@link PatchInstructionAction}, which allows the user
 * to assemble an instruction at the current address; and {@link PatchDataAction}, which allows the
 * user to "assemble" data at the current address.
 * 
 * <p>
 * The API for instruction assembly is available from {@link Assemblers}. For data assembly, the API
 * is in {@link DataType#encodeRepresentation(String, MemBuffer, Settings, int)}.
 */
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = "Patching",
	shortDescription = "Assembler",
	description = "This plugin provides functionality for assembly patching. " +
		"The assembler supports most processor languages also supported by the " +
		"disassembler. Depending on the particular processor, your mileage may vary. " +
		"We are in the process of testing and improving support for all our processors. " +
		"You can access the assembler by pressing Ctrl-Shift-G, and then modifying the " +
		"instruction in place. As you type, a content assist will guide you and provide " +
		"assembled bytes when you have a complete instruction.")
public class AssemblerPlugin extends ProgramPlugin {
	public static final String ASSEMBLER_NAME = "Assembler";

	private static final String ASSEMBLY_RATING = "assemblyRating";
	private static final String ASSEMBLY_MESSAGE = "assemblyMessage";

	/**
	 * Enumerated quality ratings and text to describe them.
	 */
	static enum AssemblyRating {
		UNRATED("This processor has not been tested with the assembler." +
			" The assembler will probably work on this language."),
		POOR("This processor received a rating of POOR during testing." +
			" We DO NOT recommend trying to assemble."),
		BRONZE("This processor received a rating of BRONZE during testing." +
			" A fair number of instructions may assemble, but we DO NOT recommend trying to" +
			" assemble."),
		SILVER("This processor received a rating of SILVER during testing." +
			" Most instructions should work, but you will likely encounter a few errors."),
		GOLD("This processor received a rating of GOLD during testing." +
			" You should rarely encounter an error."),
		PLATINUM("This processor received a rating of PLATINUM during testing.");

		final String message;

		private AssemblyRating(String message) {
			this.message = message;
		}
	}

	// To build the assembler in the background if it takes a while
	private static class AssemblerConstructorWorker extends CachingSwingWorker<Assembler> {
		private Language language;

		public AssemblerConstructorWorker(Language language) {
			super("Assemble", false);
			this.language = language;
		}

		@Override
		protected Assembler runInBackground(TaskMonitor monitor) {
			monitor.setMessage("Constructing assembler for " + language);
			return Assemblers.getAssembler(language);
		}
	}

	public static final Map<Language, CachingSwingWorker<Assembler>> CACHE =
		LazyMap.lazyMap(new HashMap<>(), language -> new AssemblerConstructorWorker(language));

	/*test*/ static final Map<Language, Boolean> SHOWN_WARNING =
		DefaultedMap.defaultedMap(new HashMap<>(), false);

	/*test*/ PatchInstructionAction patchInstructionAction;
	/*test*/ PatchDataAction patchDataAction;
	/*test*/ AssemblePatchAction assemblePatchAction;

	public AssemblerPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	protected static void warnLanguage(Language language) {
		AssemblyRating rating = AssemblyRating.valueOf(
			language.getProperty(ASSEMBLY_RATING + ":" + language.getLanguageID(),
				AssemblyRating.UNRATED.name()));
		if (AssemblyRating.PLATINUM != rating) {
			String message = language.getProperty(ASSEMBLY_MESSAGE + ":" + language.getLanguageID(),
				rating.message);
			if (!SHOWN_WARNING.get(language)) {
				Msg.showWarn(AssemblerPlugin.class, null, "Assembler Rating",
					"<html><body><p style='width: 300px;'>" + message + "</p></body></html>");
				SHOWN_WARNING.put(language, true);
			}
		}
	}

	private void createActions() {
		// Debugger provides its own "Patch" actions
		patchInstructionAction = new PatchInstructionAction(this) {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return super.isEnabledForContext(context) &&
					context instanceof ListingActionContext lac &&
					!lac.getNavigatable().isDynamic();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return super.isAddToPopup(context) &&
					context instanceof ListingActionContext lac &&
					!lac.getNavigatable().isDynamic();
			}
		};
		tool.addAction(patchInstructionAction);

		patchDataAction = new PatchDataAction(this) {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return super.isEnabledForContext(context) &&
					context instanceof ListingActionContext lac &&
					!lac.getNavigatable().isDynamic();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return super.isAddToPopup(context) &&
					context instanceof ListingActionContext lac &&
					!lac.getNavigatable().isDynamic();
			}
		};
		tool.addAction(patchDataAction);

		assemblePatchAction = new AssemblePatchAction(this, "Assemble") {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return super.isEnabledForContext(context) &&
					context instanceof ListingActionContext lac &&
					!lac.getNavigatable().isDynamic();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return super.isAddToPopup(context) &&
					context instanceof ListingActionContext lac &&
					!lac.getNavigatable().isDynamic();
			}
		};
		tool.addAction(assemblePatchAction);
	}

	@Override
	protected void dispose() {
		patchInstructionAction.dispose();
		patchDataAction.dispose();
	}
}
