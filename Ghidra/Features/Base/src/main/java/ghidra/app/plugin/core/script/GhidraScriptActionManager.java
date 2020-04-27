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
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.tool.ToolConstants;
import docking.widgets.table.GTable;
import generic.jar.ResourceFile;
import ghidra.app.script.*;
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

	private GhidraScriptComponentProvider provider;
	private GhidraScriptMgrPlugin plugin;
	private GhidraScriptInfoManager infoManager;
	private DockingAction refreshAction;
	private DockingAction bundleStatusAction;
	private DockingAction newAction;
	private DockingAction runAction;
	private DockingAction runLastAction;
	private DockingAction globalRunLastAction;
	private DockingAction editAction;
	private DockingAction eclipseAction;
	private DockingAction deleteAction;
	private DockingAction renameAction;
	private DockingAction keyBindingAction;
	private DockingAction helpAction;
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
		List<ResourceFile> dirs = GhidraScriptUtil.getScriptSourceDirectories();
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
			ScriptInfo info = infoManager.findScriptByName(filename);
			if (info != null) { // the file may have been deleted from disk
				provider.getActionManager().createAction(info.getSourceFile());
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
			scriptPaths.add(file.getName());
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

	private void createActions() {
		//
		// 'run' actions
		//
		String runGroup = "1";
		runAction = new DockingAction("Run", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.runScript();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject instanceof ResourceFile;
			}
		};
		runAction.setPopupMenuData(new MenuData(new String[] { "Run" },
			ResourceManager.loadImage("images/play.png"), null));
		runAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/play.png"), runGroup));

		runAction.setDescription("Run Script");
		runAction.setEnabled(false);
		plugin.getTool().addLocalAction(provider, runAction);

		runLastAction = new RerunLastScriptAction(runGroup);
		plugin.getTool().addLocalAction(provider, runLastAction);
		globalRunLastAction = new RerunLastScriptAction("Xtra");
		plugin.getTool().addAction(globalRunLastAction);

		//
		// End 'run' actions
		//

		editAction = new DockingAction("Edit", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.editScriptBuiltin();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject instanceof ResourceFile;
			}
		};
		editAction.setPopupMenuData(new MenuData(new String[] { "Edit with basic editor" },
			ResourceManager.loadImage("images/accessories-text-editor.png"), null));
		editAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/accessories-text-editor.png"), null));
		editAction.setDescription("Edit Script with basic editor");
		editAction.setEnabled(false);
		plugin.getTool().addLocalAction(provider, editAction);

		eclipseAction = new DockingAction("EditEclipse", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.editScriptEclipse();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject instanceof ResourceFile;
			}
		};
		eclipseAction.setPopupMenuData(new MenuData(new String[] { "Edit with Eclipse" },
			ResourceManager.loadImage("images/eclipse.png"), null));
		eclipseAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/eclipse.png"), null));
		eclipseAction.setDescription("Edit Script with Eclipse");
		eclipseAction.setEnabled(false);
		plugin.getTool().addLocalAction(provider, eclipseAction);

		keyBindingAction = new DockingAction("Key Binding", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.assignKeyBinding();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject instanceof ResourceFile;
			}
		};
		keyBindingAction.setPopupMenuData(new MenuData(new String[] { "Assign Key Binding" },
			ResourceManager.loadImage("images/key.png"), null));
		keyBindingAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/key.png"), null));

		keyBindingAction.setDescription("Assign Key Binding");
		keyBindingAction.setEnabled(false);
		plugin.getTool().addLocalAction(provider, keyBindingAction);

		deleteAction = new DockingAction("Delete", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.deleteScript();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject instanceof ResourceFile;
			}
		};
		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" },
			ResourceManager.loadImage("images/edit-delete.png"), null));
		deleteAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/edit-delete.png"), null));

		deleteAction.setDescription("Delete Script");
		deleteAction.setEnabled(false);
		plugin.getTool().addLocalAction(provider, deleteAction);

		renameAction = new DockingAction("Rename", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.renameScript();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject instanceof ResourceFile;
			}
		};
		renameAction.setPopupMenuData(new MenuData(new String[] { "Rename" },
			ResourceManager.loadImage("images/textfield_rename.png"), null));
		renameAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/textfield_rename.png"), null));

		renameAction.setDescription("Rename Script");
		renameAction.setEnabled(false);
		plugin.getTool().addLocalAction(provider, renameAction);

		newAction = new DockingAction("New", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.newScript();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object contextObject = context.getContextObject();
				return (contextObject instanceof GTable) || (contextObject instanceof ResourceFile);
			}
		};
		newAction.setPopupMenuData(new MenuData(new String[] { "New" },
			ResourceManager.loadImage("images/script_add.png"), null));
		newAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/script_add.png"), null));

		newAction.setDescription("Create New Script");
		newAction.setEnabled(true);
		plugin.getTool().addLocalAction(provider, newAction);

		refreshAction = new DockingAction("Refresh", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.refresh();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object contextObject = context.getContextObject();
				return (contextObject instanceof GTable) || (contextObject instanceof ResourceFile);
			}
		};
		refreshAction.setPopupMenuData(
			new MenuData(new String[] { "Refresh" }, Icons.REFRESH_ICON, null));
		refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));

		refreshAction.setDescription("Refresh Script List");
		refreshAction.setEnabled(true);
		plugin.getTool().addLocalAction(provider, refreshAction);

		bundleStatusAction = new DockingAction("Bundle Status", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.showBundleStatusComponent();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object contextObject = context.getContextObject();
				return (contextObject instanceof GTable) || (contextObject instanceof ResourceFile);
			}
		};
		bundleStatusAction.setPopupMenuData(new MenuData(new String[] { "Bundle Status" },
			ResourceManager.loadImage("images/text_list_bullets.png"), null));
		bundleStatusAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/text_list_bullets.png"), null));

		bundleStatusAction.setDescription("Bundle Status");
		bundleStatusAction.setEnabled(true);
		plugin.getTool().addLocalAction(provider, bundleStatusAction);

		helpAction = new DockingAction("Ghidra API Help", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showGhidraScriptJavadoc();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return (contextObject instanceof GTable) || (contextObject instanceof ResourceFile);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object contextObject = context.getContextObject();
				return (contextObject instanceof GTable) || (contextObject instanceof ResourceFile);
			}
		};

		helpAction.setPopupMenuData(new MenuData(new String[] { "Ghidra API Help" },
			ResourceManager.loadImage("images/red-cross.png"), null));
		helpAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/red-cross.png"), null));

		helpAction.setDescription("Help");
		helpAction.setEnabled(true);
		helpAction.setHelpLocation(new HelpLocation(plugin.getName(), "Help"));
		plugin.getTool().addLocalAction(provider, helpAction);

		DockingAction globalHelpAction = new DockingAction("Ghidra API Help", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showGhidraScriptJavadoc();
			}

			@Override
			public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
				return true;
			}
		};
		globalHelpAction.setEnabled(true);
		globalHelpAction.setHelpLocation(new HelpLocation("Misc", "Welcome_to_Ghidra_Help"));
		globalHelpAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_HELP, "Ghidra API Help" }, null,
				ToolConstants.HELP_CONTENTS_MENU_GROUP));
		plugin.getTool().addAction(globalHelpAction);

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
		return new HelpLocation(plugin.getName(), bundleStatusAction.getName());
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
			try (ZipFile zf = new ZipFile(zipFile)) {

				// Check to see if zip file has been extracted already
				if (versionedExtractDir.exists()) {

					// Open Javadoc if all the files are present
					if (zf.size() + 1 == Files.walk(versionedExtractDir.toPath()).count()) {
						launchJavadoc();
						return;
					}

					// Delete corrupted directory and continue
					cleanup(monitor, versionedExtractDir);
				}

				monitor.setMessage("Preparing to extract Ghidra API javadoc...");
				monitor.initialize(zf.size());

				Enumeration<? extends ZipEntry> entries = zf.entries();
				while (entries.hasMoreElements()) {
					if (monitor.isCancelled()) {
						cleanup(monitor, versionedExtractDir);
						return;
					}

					ZipEntry entry = entries.nextElement();
					monitor.setMessage("Extracting " + entry.getName() + "...");
					writeZipEntry(versionedExtractDir, entry, zf.getInputStream(entry));
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
			URI URI = entryFile.toURI();
			URL URL = null;
			try {
				URL = URI.toURL();
			}
			catch (MalformedURLException e) {
				// shouldn't happen
				Msg.showError(GhidraScriptActionManager.this, provider.getComponent(),
					"Unexpected Error Showing Script Help",
					"Unexpectedly could not create a URL for the GhidraScript javadoc", e);
				return;
			}

			BrowserLoader.display(URL, URL, plugin.getTool());
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
