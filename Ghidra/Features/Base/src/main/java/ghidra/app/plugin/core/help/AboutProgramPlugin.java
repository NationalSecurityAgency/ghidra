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
package ghidra.app.plugin.core.help;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.GenericHelpTopics;
import ghidra.app.util.HelpTopics;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.HelpLocation;

/**
 * Display a pop-up dialog containing information about the Domain Object that is currently open in
 * the tool.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Displays program information",
	description = "This plugin provides an action that displays information about the currently loaded program"
)
//@formatter:on
public class AboutProgramPlugin extends Plugin implements ApplicationLevelPlugin {
	public final static String PLUGIN_NAME = "AboutProgramPlugin";
	public final static String ACTION_NAME = "About Program";

	private DockingAction aboutAction;

	public AboutProgramPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		setupActions();
	}

	@Override
	public void dispose() {
		tool.removeAction(aboutAction);
		aboutAction.dispose();
		super.dispose();
	}

	record LcspAndVersion(Language language, CompilerSpec compilerSpec, Integer languageVersion,
			Integer languageMinorVersion) {
		public static final Pattern LANG_PAT =
			Pattern.compile("(?<id>\\S+) \\((?<major>\\d+)\\.(?<minor>\\d+)\\)");

		static Language tryLang(String languageID) {
			LanguageService langServ = DefaultLanguageService.getLanguageService();
			try {
				return langServ.getLanguage(new LanguageID(languageID));
			}
			catch (LanguageNotFoundException e) {
				return null;
			}
		}

		static Integer tryInt(String i) {
			try {
				return Integer.parseInt(i);
			}
			catch (NumberFormatException e) {
				return null;
			}
		}

		static CompilerSpec tryCompiler(Language language, String compilerSpecID) {
			try {
				return language.getCompilerSpecByID(new CompilerSpecID(compilerSpecID));
			}
			catch (CompilerSpecNotFoundException e) {
				return null;
			}
		}

		/**
		 * @see ProgramDB#getMetadata()
		 * @param metadata the metadata
		 * @return the parsed language, compiler spec, and language version
		 */
		public static LcspAndVersion fromMetadata(Map<String, String> metadata) {
			String languageInfo = metadata.get("Language ID");
			if (languageInfo == null) {
				return null;
			}
			Matcher matcher = LANG_PAT.matcher(languageInfo);
			Language language;
			Integer languageVersion;
			Integer languageMinorVersion;
			if (matcher.matches()) {
				language = tryLang(matcher.group("id"));
				languageVersion = tryInt(matcher.group("major"));
				languageMinorVersion = tryInt(matcher.group("minor"));
			}
			else {
				language = tryLang(languageInfo);
				languageVersion = null;
				languageMinorVersion = null;
			}
			if (language == null) {
				return null;
			}

			String compilerInfo = metadata.get("Compiler ID");
			if (compilerInfo == null) {
				return new LcspAndVersion(language, null, languageVersion, languageMinorVersion);
			}
			CompilerSpec compilerSpec = tryCompiler(language, compilerInfo);
			return new LcspAndVersion(language, compilerSpec, languageVersion,
				languageMinorVersion);
		}

		public boolean isMismatch() {
			return !Objects.equals(language.getVersion(), languageVersion) ||
				!Objects.equals(language.getMinorVersion(), languageMinorVersion);
		}

		public String getVersionDisplay() {
			if (language == null) {
				return "";
			}
			return " (%d.%d)".formatted(language.getVersion(), language.getMinorVersion());
		}
	}

	private void addLanguageFileInfo(Map<String, String> metadata) {
		LcspAndVersion lav = LcspAndVersion.fromMetadata(metadata);
		if (lav == null || lav.language == null) {
			return;
		}
		if (lav.language.getLanguageDescription() instanceof SleighLanguageDescription lDesc) {
			metadata.put("Language Spec",
				lDesc.getDefsFile() + (lav.isMismatch() ? lav.getVersionDisplay() : ""));
			metadata.put("Processor Spec", lDesc.getSpecFile().getAbsolutePath());
			metadata.put("Sleigh Spec", lDesc.getSlaFile().getAbsolutePath() + "spec");
		}
		if (lav.compilerSpec != null) {
			metadata.put("Compiler Spec",
				lav.compilerSpec.getCompilerSpecDescription().getSource());
		}
	}

	private void setupActions() {
		if (tool instanceof FrontEndTool) {
			aboutAction = new FrontendProjectTreeAction(ACTION_NAME, PLUGIN_NAME) {

				@Override
				protected void actionPerformed(ProjectDataContext context) {
					DomainFile domainFile = context.getSelectedFiles().get(0);
					Map<String, String> metadata = new LinkedHashMap<>(domainFile.getMetadata());
					addLanguageFileInfo(metadata);
					showAbout(domainFile, metadata);
				}

				@Override
				protected boolean isAddToPopup(ProjectDataContext context) {
					if (context.getFileCount() == 1 && context.getFolderCount() == 0) {
						// Adjust popup menu text
						DomainFile domainFile = context.getSelectedFiles().get(0);
						String contentType = domainFile.getContentType();
						setPopupMenuData(
							new MenuData(new String[] { "About " + contentType }, null, "AAA"));
						return true;
					}
					return false;
				}
			};
			aboutAction.setPopupMenuData(new MenuData(new String[] { ACTION_NAME }, null, "AAA"));

			aboutAction.setEnabled(true);
		}
		else {
			aboutAction = new ProgramContextAction(ACTION_NAME, PLUGIN_NAME) {
				@Override
				public void actionPerformed(ProgramActionContext context) {
					Program program = context.getProgram();
					Map<String, String> metadata = new LinkedHashMap<>(program.getMetadata());
					addLanguageFileInfo(metadata);
					showAbout(program.getDomainFile(), metadata);
				}

				@Override
				public boolean isValidContext(ActionContext context) {
					if (super.isValidContext(context)) {
						ProgramActionContext pac = (ProgramActionContext) context;
						Program program = pac.getProgram();
						if (program != null) {
							getMenuBarData().setMenuItemNamePlain(
								"About " + program.getDomainFile().getName());
							return true;
						}
					}
					getMenuBarData().setMenuItemName(ACTION_NAME);
					return false;
				}
			};
			aboutAction.addToWindowWhen(ProgramActionContext.class);
			// use the CodeBrowser as a backup context provider
			aboutAction.setContextClass(ProgramActionContext.class, true);

			aboutAction.setMenuBarData(
				new MenuData(new String[] { ToolConstants.MENU_HELP, ACTION_NAME }, null, "ZZZ"));

			aboutAction.setEnabled(false);
		}

		aboutAction.setHelpLocation(new HelpLocation(HelpTopics.ABOUT, "About_Program"));
		aboutAction.setDescription(getPluginDescription().getDescription());
		tool.addAction(aboutAction);
	}

	private void showAbout(DomainFile domainFile, Map<String, String> metadata) {
		HelpLocation helpLocation = new HelpLocation(GenericHelpTopics.ABOUT, "About_Program");
		AboutDomainObjectUtils.displayInformation(tool, domainFile, metadata,
			"About " + domainFile.getName(), null, helpLocation);
	}

}
