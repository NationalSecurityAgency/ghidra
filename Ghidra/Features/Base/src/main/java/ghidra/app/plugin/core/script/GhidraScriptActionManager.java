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
package ghidra.app.plugin.core.script;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.actions.KeyBindingUtils;
import docking.tool.ToolConstants;
import docking.widgets.table.GTable;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptInfoManager;
import ghidra.app.script.ScriptInfo;
import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.util.*;
import ghidra.util.task.*;
import resources.Icons;
import resources.ResourceManager;
import utilities.util.FileUtilities;

class GhidraScriptActionManager {
	public static final String RERUN_LAST_SHARED_ACTION_NAME = "Rerun Last Script";
	private static final KeyStroke RERUN_LAST_SCRIPT_KEYSTROKE = KeyStroke.getKeyStroke(
		KeyEvent.VK_R, DockingUtils.CONTROL_KEY_MODIFIER_MASK | InputEvent.SHIFT_DOWN_MASK);
	private static final String SCRIPT_ACTIONS_KEY = "Scripts_Actions_Key";

	private static final String RESOURCE_FILE_ACTION_RUN_GROUP = "1";

	private GhidraScriptComponentProvider provider;
	private GhidraScriptMgrPlugin plugin;
	private GhidraScriptInfoManager infoManager;
	private DockingAction showBundleStatusAction;
	private DockingAction newAction;
	private DockingAction runLastAction;
	private DockingAction globalRunLastAction;
	private DockingAction renameAction;
	private DockingAction keyBindingAction;
	private Map<ResourceFile, ScriptAction> actionMap = new HashMap<>();

	GhidraScriptActionManager(GhidraScriptComponentProvider provider, GhidraScriptMgrPlugin plugin,
			GhidraScriptInfoManager infoManager) {
		this.provider = provider;
		this.plugin = plugin;
		this.infoManager = infoManager;
		createActions();
	}

	void dispose() {
		actionMap.values().forEach(ScriptAction::dispose);
		actionMap.clear();
	}

	void restoreUserDefinedKeybindings(SaveState saveState) {
		Collection<ResourceFile> dirs = provider.getBundleHost().getBundleFiles();
		String[] names = saveState.getNames();

		for (String name : names) {
			for (ResourceFile dir : dirs) {
				ResourceFile script = new ResourceFile(dir, name);
				if (!script.exists()) {
					continue;
				}

				ScriptAction action = createAction(script);
				String strokeStr = saveState.getString(name, null);
				if (strokeStr == null || strokeStr.length() == 0) {
					action.setKeyBindingData(null);
				}
				else {
					KeyStroke stroke = KeyBindingUtils.parseKeyStroke(strokeStr);
					if (stroke == null) {
						break;
					}
					action.setKeyBindingData(new KeyBindingData(stroke));
				}
			}
		}
	}

	void restoreScriptsThatAreInTool(SaveState saveState) {
		String[] array = saveState.getStrings(SCRIPT_ACTIONS_KEY, new String[0]);
		for (String filename : array) {
			ResourceFile file = generic.util.Path.fromPathString(filename);
			if (file.exists()) {
				// restore happens early -- the next call will create a new ScriptInfo
				ScriptInfo info = infoManager.getScriptInfo(file);
				if (info != null) {
					createAction(info.getSourceFile());
				}
			}
			else {
				Msg.info(this, "Cannot find script for keybinding: '" + filename + "'");
			}
		}
	}

	/**
	 * This saves bindings that users have changed.  These will overwrite those that may
	 * be defined in the script.
	 * @param saveState the state into which bindings are saved
	 */
	void saveUserDefinedKeybindings(SaveState saveState) {
		Collection<ScriptAction> actions = actionMap.values();
		for (ScriptAction action : actions) {
			if (!action.isUserDefinedKeyBinding()) {
				continue;
			}
			ResourceFile scriptFile = action.getScript();
			ScriptInfo info = infoManager.getExistingScriptInfo(scriptFile);
			if (info == null) {
				Msg.showError(this, provider.getComponent(), "Bad state?",
					"action associated with a script that has no info");
				continue;//bad state?
			}

			KeyStroke stroke = action.getKeyBinding();
			if (stroke == null) {
				saveState.putString(scriptFile.getName(), "");
			}
			else {
				String strokeStr = KeyBindingUtils.parseKeyStroke(stroke);
				saveState.putString(scriptFile.getName(), strokeStr);
			}
		}
	}

	/**
	 * This saves scripts that not only have keybindings, but that are also marked as "In Tool"
	 * from the GUI.
	 * @param saveState the state into which the script info is saved
	 */
	void saveScriptsThatAreInTool(SaveState saveState) {
		Set<ResourceFile> actionScriptFiles = actionMap.keySet();
		Set<String> scriptPaths = new HashSet<>(actionScriptFiles.size());
		for (ResourceFile file : actionScriptFiles) {
			scriptPaths.add(generic.util.Path.toPathString(file));
		}

		String[] array = scriptPaths.toArray(new String[scriptPaths.size()]);
		saveState.putStrings(SCRIPT_ACTIONS_KEY, array);
	}

	/**
	 * Notifies this script action manager that a script has been run.
	 */
	void notifyScriptWasRun() {
		String newDesc = "Rerun " + provider.getLastRunScript().getName();
		runLastAction.firePropertyChanged(DockingActionIf.DESCRIPTION_PROPERTY, "", newDesc);
		globalRunLastAction.firePropertyChanged(DockingActionIf.DESCRIPTION_PROPERTY, "", newDesc);
	}

	private DockingAction createScriptAction(String name, String menuEntry, String description,
			Icon icon, String toolBarGroup, Runnable runnable) {
		return new ActionBuilder(name, plugin.getName()).popupMenuPath(menuEntry)
				.popupMenuIcon(icon)
				.toolBarIcon(icon)
				.toolBarGroup(toolBarGroup)
				.description(description)
				.enabled(false)
				.enabledWhen(context -> context.getContextObject() instanceof ResourceFile)
				.onAction(context -> runnable.run())
				.buildAndInstallLocal(provider);
	}

	private DockingAction createScriptTableAction(String name, String description, Icon icon,
			Runnable runnable) {
		return new ActionBuilder(name, plugin.getName()).popupMenuPath(name)
				.popupMenuIcon(icon)
				.toolBarIcon(icon)
				.toolBarGroup(null)
				.description(description)
				.enabledWhen(context -> {
					Object contextObject = context.getContextObject();
					return (contextObject instanceof GTable) ||
						(contextObject instanceof ResourceFile);
				})
				.onAction(context -> runnable.run())
				.buildAndInstallLocal(provider);
	}

	private void createActions() {
		createScriptAction("Run", "Run Script", "Run Script",
			ResourceManager.loadImage("images/play.png"), RESOURCE_FILE_ACTION_RUN_GROUP,
			provider::runScript);

		runLastAction = new RerunLastScriptAction(RESOURCE_FILE_ACTION_RUN_GROUP);
		plugin.getTool().addLocalAction(provider, runLastAction);

		globalRunLastAction = new RerunLastScriptAction("Xtra");
		plugin.getTool().addAction(globalRunLastAction);

		createScriptAction("Edit", "Edit with basic editor", "Edit Script with basic editor",
			ResourceManager.loadImage("images/accessories-text-editor.png"), null,
			provider::editScriptBuiltin);

		createScriptAction("EditEclipse", "Edit with Eclipse", "Edit Script with Eclipse",
			ResourceManager.loadImage("images/eclipse.png"), null, provider::editScriptEclipse);

		keyBindingAction =
			createScriptAction("Key Binding", "Assign Key Binding", "Assign Key Binding",
				ResourceManager.loadImage("images/key.png"), null, provider::assignKeyBinding);

		createScriptAction("Delete", "Delete", "Delete Script",
			ResourceManager.loadImage("images/edit-delete.png"), null, provider::deleteScript);

		renameAction = createScriptAction("Rename", "Rename", "Rename Script",
			ResourceManager.loadImage("images/textfield_rename.png"), null, provider::renameScript);

		newAction = createScriptTableAction("New", "Create New Script",
			ResourceManager.loadImage("images/script_add.png"), provider::newScript);

		createScriptTableAction("Refresh", "Refresh Script List", Icons.REFRESH_ICON,
			provider::refresh);

		showBundleStatusAction = createScriptTableAction("Script Directories",
			"Manage Script Directories", ResourceManager.loadImage("images/text_list_bullets.png"),
			provider::showBundleStatusComponent);

		Icon icon = ResourceManager.loadImage("images/red-cross.png");
		Predicate<ActionContext> test = context -> {
			Object contextObject = context.getContextObject();
			return (contextObject instanceof GTable) || (contextObject instanceof ResourceFile);
		};

		new ActionBuilder("Ghidra API Help", plugin.getName()).popupMenuPath("Ghidra API Help")
				.popupMenuIcon(icon)
				.popupWhen(test)
				.toolBarIcon(icon)
				.toolBarGroup(null)
				.description("Help")
				.helpLocation(new HelpLocation(plugin.getName(), "Help"))
				.enabledWhen(test)
				.onAction(context -> showGhidraScriptJavadoc())
				.buildAndInstallLocal(provider);

		new ActionBuilder("Ghidra API Help", plugin.getName())
				.menuGroup(ToolConstants.HELP_CONTENTS_MENU_GROUP)
				.menuPath(ToolConstants.MENU_HELP, "Ghidra API Help")
				.helpLocation(new HelpLocation("Misc", "Welcome_to_Ghidra_Help"))
				.inWindow(ActionBuilder.When.ALWAYS)
				.onAction(context -> showGhidraScriptJavadoc())
				.buildAndInstall(plugin.getTool());
	}

	private void showGhidraScriptJavadoc() {
		// we currently place the API docs inside of the <user dir>/docs

		if (SystemUtilities.isInDevelopmentMode()) {
			Msg.showWarn(GhidraScriptActionManager.this, provider.getComponent(),
				"Error Unzipping Javadoc File", "Cannot view Ghidra API Help in development mode.");
			return;
		}
		File zipFile = new File(Application.getInstallationDirectory().getFile(false),
			"docs/GhidraAPI_javadoc.zip");
		String version = Application.getApplicationVersion();
		File extractDir = new File(Application.getUserCacheDirectory(), "GhidraAPI_javadoc");
		File entryFile = new File(extractDir, version + "/api/ghidra/app/script/GhidraScript.html");
		LaunchJavadocTask task = new LaunchJavadocTask(zipFile, extractDir, entryFile, version);
		new TaskLauncher(task, this.provider.getComponent()); // run the task
	}

	HelpLocation getPathHelpLocation() {
		return new HelpLocation(plugin.getName(), showBundleStatusAction.getName());
	}

	HelpLocation getKeyBindingHelpLocation() {
		return new HelpLocation(plugin.getName(), keyBindingAction.getName());
	}

	HelpLocation getRenameHelpLocation() {
		return new HelpLocation(plugin.getName(), renameAction.getName());
	}

	HelpLocation getNewHelpLocation() {
		return new HelpLocation(plugin.getName(), newAction.getName());
	}

	ScriptAction get(ResourceFile script) {
		return actionMap.get(script);
	}

	boolean hasScriptAction(ResourceFile script) {
		return actionMap.containsKey(script);
	}

	synchronized ScriptAction createAction(ResourceFile script) {
		ScriptAction action = actionMap.get(script);
		if (action == null) {
			action = new ScriptAction(plugin, script);
			actionMap.put(script, action);
		}
		return action;
	}

	synchronized void removeAction(ResourceFile script) {
		ScriptAction action = actionMap.remove(script);
		if (action != null) {
			action.dispose();
			plugin.getTool().removeAction(action);
		}
	}

	KeyStroke getKeyBinding(ResourceFile script) {
		ScriptAction action = actionMap.get(script);
		if (action != null) {
			return action.getKeyBinding();
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class LaunchJavadocTask extends Task {

		private final File zipFile;
		private final File extractDir;
		private final File entryFile;
		private final String version;

		LaunchJavadocTask(File zipFile, File extractDir, File entryFile, String version) {
			super("Extract Javadoc Task", true, true, true);
			this.zipFile = zipFile;
			this.extractDir = extractDir;
			this.entryFile = entryFile;
			this.version = version;
		}

		@Override
		public void run(TaskMonitor monitor) {

			// Make sure zip file is where we think it is
			if (!zipFile.exists()) {
				Msg.showError(GhidraScriptActionManager.this, provider.getComponent(),
					"Unexpected Error Unzipping Javadoc File", "Javadoc zip file does not " +
						"exist at expected path: " + zipFile.getAbsolutePath());
				return;
			}

			// Cleanup javadoc from old versions of Ghidra
			if (extractDir.exists()) {
				for (File dir : extractDir.listFiles(File::isDirectory)) {
					if (!dir.getName().equals(version)) {
						cleanup(monitor, dir);
					}
				}
			}

			File versionedExtractDir = new File(extractDir, version);
			try (ZipFile zipFileObject = new ZipFile(zipFile)) {

				// Check to see if zip file has been extracted already
				if (versionedExtractDir.exists()) {

					// Open Javadoc if all the files are present
					try (Stream<Path> walk = Files.walk(versionedExtractDir.toPath())) {
						if (zipFileObject.size() + 1 == walk.count()) {
							launchJavadoc();
							return;
						}
					}

					// Delete corrupted directory and continue
					cleanup(monitor, versionedExtractDir);
				}

				monitor.setMessage("Preparing to extract Ghidra API javadoc...");
				monitor.initialize(zipFileObject.size());

				Enumeration<? extends ZipEntry> entries = zipFileObject.entries();
				while (entries.hasMoreElements()) {
					if (monitor.isCancelled()) {
						cleanup(monitor, versionedExtractDir);
						return;
					}

					ZipEntry entry = entries.nextElement();
					monitor.setMessage("Extracting " + entry.getName() + "...");
					writeZipEntry(versionedExtractDir, entry, zipFileObject.getInputStream(entry));
					monitor.incrementProgress(1);
				}

				monitor.setMessage("Launching native viewer for " + entryFile.getName());
				launchJavadoc();
			}
			catch (IOException e) {
				Msg.showError(GhidraScriptActionManager.this, provider.getComponent(),
					"Unexpected Error Unzipping Javadoc File",
					"Unexpected error unzipping javadoc file", e);

				cleanup(monitor, versionedExtractDir);
			}
		}

		private void cleanup(TaskMonitor monitor, File dir) {
			monitor.setMessage("Deleting " + dir.getName() + "...");
			FileUtilities.deleteDir(dir);
		}

		private void launchJavadoc() {
			URI uri = entryFile.toURI();
			URL url = null;
			try {
				url = uri.toURL();
			}
			catch (MalformedURLException e) {
				// shouldn't happen
				Msg.showError(GhidraScriptActionManager.this, provider.getComponent(),
					"Unexpected Error Showing Script Help",
					"Unexpectedly could not create a URL for the GhidraScript javadoc", e);
				return;
			}

			BrowserLoader.display(url, url, plugin.getTool());
		}

		private void writeZipEntry(File unzipDirectory, ZipEntry entry, InputStream inputStream)
				throws IOException {
			String zipName = entry.getName();
			if (zipName.endsWith("/")) {
				new File(unzipDirectory, zipName).mkdirs();
				return;
			}

			File file = new File(unzipDirectory, zipName);
			mkdirs(file); // make sure the output path exists
			FileOutputStream ouputStream = new FileOutputStream(file);
			byte[] buffer = new byte[1024];
			int bytesRead = -1;
			while ((bytesRead = inputStream.read(buffer)) != -1) {
				ouputStream.write(buffer, 0, bytesRead);
			}

			inputStream.close();
			ouputStream.close();
		}

		private void mkdirs(File file) {
			String filename = file.getName();
			if (filename.endsWith("/")) {
				// this is a dir
				file.mkdirs();
			}
			else {
				File parentFile = file.getParentFile();
				parentFile.mkdirs();
			}
		}

	}

	private class RerunLastScriptAction extends DockingAction {

		RerunLastScriptAction(String toolbarGroup) {
			super(RERUN_LAST_SHARED_ACTION_NAME, plugin.getName(), KeyBindingType.SHARED);

			setToolBarData(
				new ToolBarData(ResourceManager.loadImage("images/play_again.png"), toolbarGroup));
			setDescription("Rerun the last run script");
			setHelpLocation(new HelpLocation(plugin.getName(), "Run_Last"));

			initKeyStroke(RERUN_LAST_SCRIPT_KEYSTROKE);
		}

		private void initKeyStroke(KeyStroke keyStroke) {
			if (keyStroke == null) {
				return;
			}

			setKeyBindingData(new KeyBindingData(keyStroke));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			provider.runLastScript();
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return provider.getLastRunScript() != null;
		}
	}
}
