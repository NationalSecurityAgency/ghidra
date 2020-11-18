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
package ghidra.app.plugin.core.clipboard;

import java.awt.Window;
import java.awt.datatransfer.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.JFrame;
import javax.swing.event.ChangeListener;

import docking.*;
import docking.action.*;
import docking.dnd.GClipboard;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.services.ClipboardService;
import ghidra.app.util.ClipboardType;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.*;
import resources.ResourceManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Clipboard Manager",
	description = "This plugin manages cut/copy/paste of labels, comments, formatted code, and byte strings to and from the system clipboard.",
	servicesProvided = { ClipboardService.class }
)
//@formatter:on
public class ClipboardPlugin extends ProgramPlugin implements ClipboardOwner, ClipboardService {

	public static final String GROUP_NAME = "Clipboard";
	public static final String TOOLBAR_GROUP_NAME = "ZClipboard";

	//The provider that owns the clipboard content
	private ClipboardContentProviderService clipboardOwnerProvider;

	private Map<ClipboardContentProviderService, List<DockingAction>> serviceActionMap =
		new HashMap<>();

	//The last type used by copy special
	private Map<ClipboardContentProviderService, ClipboardType> lastUsedCopySpecialType =
		new HashMap<>();

	private ChangeListener changeListener = e -> {
		updateCopyState();
		updatePasteState();
	};

	private boolean isClipboardOwner;

	public ClipboardPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	protected void dispose() {
		removeAllActions();
		clearClipboardContents();
		super.dispose();
	}

	@Override
	protected void programDeactivated(Program program) {
		if (clipboardOwnerProvider != null) {
			clipboardOwnerProvider.lostOwnership(null);
		}
		clipboardOwnerProvider = null;
	}

	@Override
	public void registerClipboardContentProvider(ClipboardContentProviderService service) {
		initializeLocalActions(service);
		service.addChangeListener(changeListener);
	}

	@Override
	public void deRegisterClipboardContentProvider(ClipboardContentProviderService service) {
		List<DockingAction> actionList = serviceActionMap.get(service);
		if (actionList != null) {
			removeLocalActions(service, actionList);
		}
		serviceActionMap.remove(service);
		service.removeChangeListener(changeListener);
	}

	private void initializeLocalActions(ClipboardContentProviderService clipboardService) {
		// don't add the actions twice
		List<DockingAction> list = serviceActionMap.get(clipboardService);
		if (list != null) {
			return;
		}

		List<DockingAction> actionList = createActions(clipboardService);
		serviceActionMap.put(clipboardService, actionList);
		addLocalActions(clipboardService, actionList);
	}

	private void addLocalActions(ClipboardContentProviderService clipboardService,
			List<DockingAction> actionList) {
		ComponentProvider componentProvider = clipboardService.getComponentProvider();
		for (DockingAction pluginAction : actionList) {
			tool.addLocalAction(componentProvider, pluginAction);
		}
	}

	private void removeLocalActions(ClipboardContentProviderService clipboardService,
			List<DockingAction> actionList) {
		if (tool == null) {
			return; // can happen during closing the tool
		}

		ComponentProvider componentProvider = clipboardService.getComponentProvider();
		for (DockingAction pluginAction : actionList) {
			tool.removeLocalAction(componentProvider, pluginAction);
		}
	}

	private void removeAllActions() {
		Set<Entry<ClipboardContentProviderService, List<DockingAction>>> entrySet =
			serviceActionMap.entrySet();
		for (Map.Entry<ClipboardContentProviderService, List<DockingAction>> entry : entrySet) {
			ClipboardContentProviderService clipboardService = entry.getKey();
			List<DockingAction> actionList = entry.getValue();
			removeLocalActions(clipboardService, actionList);
		}
	}

	private List<DockingAction> createActions(ClipboardContentProviderService clipboardService) {
		List<DockingAction> actionList = new ArrayList<>(5);

		if (clipboardService.enableCopy()) {
			actionList.add(new CopyAction(clipboardService));
		}
		if (clipboardService.enableCopySpecial()) {
			actionList.add(new CopySpecialAction(clipboardService));
			actionList.add(new CopySpecialAgainAction(clipboardService));
		}

		if (clipboardService.enablePaste()) {
			actionList.add(new PasteAction(clipboardService));
		}

		return actionList;
	}

	/**
	 * @see java.awt.datatransfer.ClipboardOwner#lostOwnership(java.awt.datatransfer.Clipboard, java.awt.datatransfer.Transferable)
	 */
	@Override
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
		if (clipboardOwnerProvider != null) {
			clipboardOwnerProvider.lostOwnership(contents);
		}
		clipboardOwnerProvider = null;
		updatePasteState();
	}

	private void setClipboardContents(Clipboard systemClipboard, Transferable transferable) {
		systemClipboard.setContents(transferable, ClipboardPlugin.this);
		isClipboardOwner = true;
	}

	private void clearClipboardContents() {
		if (isClipboardOwner) {
			isClipboardOwner = false;
			Clipboard systemClipboard = getSystemClipboard();
			systemClipboard.setContents(new DummyTransferable(), (clipboard, contents) -> {
				// dummy listener so that we can be properly garbage collected
			});
		}
	}

	private void updateCopyState() {
		Set<Entry<ClipboardContentProviderService, List<DockingAction>>> entrySet =
			serviceActionMap.entrySet();
		for (Map.Entry<ClipboardContentProviderService, List<DockingAction>> entry : entrySet) {
			ClipboardContentProviderService clipboardService = entry.getKey();
			List<DockingAction> actionList = entry.getValue();
			for (DockingAction pluginAction : actionList) {
				if (pluginAction instanceof ICopy) {
					pluginAction.setEnabled(clipboardService.canCopy());
				}
			}
		}
	}

	private void updatePasteState() {
		if (tool == null) {
			return; // this can happen during shutdown, when we lose ownership
		}

		JFrame toolFrame = tool.getToolFrame();
		if (toolFrame == null) {
			return; // this can happen during shutdown, when we lose ownership
		}

		Clipboard systemClipboard = getSystemClipboard();
		DataFlavor[] availableDataFlavors = getAvailableDataFlavors(systemClipboard);
		Set<Entry<ClipboardContentProviderService, List<DockingAction>>> entrySet =
			serviceActionMap.entrySet();
		for (Map.Entry<ClipboardContentProviderService, List<DockingAction>> entry : entrySet) {
			ClipboardContentProviderService clipboardService = entry.getKey();
			List<DockingAction> actionList = entry.getValue();
			for (DockingAction pluginAction : actionList) {
				if (pluginAction instanceof IPaste) {
					pluginAction.setEnabled(clipboardService.canPaste(availableDataFlavors));
				}
			}
		}
	}

	private void copy(final ClipboardContentProviderService clipboardService) {
		Task copyTask = new Task("Copying", true, false, true) {
			@Override
			public void run(TaskMonitor monitor) {
				monitor.setMessage("Setting Clipboard Contents");
				Clipboard systemClipboard = getSystemClipboard();
				Transferable transferable = clipboardService.copy(monitor);
				if (transferable == null) {
					return;
				}
				if (clipboardOwnerProvider != null) {
					clipboardOwnerProvider.lostOwnership(null);
				}

				setClipboardContents(systemClipboard, transferable);
				clipboardOwnerProvider = clipboardService;
				updatePasteState();
			}
		};

		new TaskLauncher(copyTask, clipboardService.getComponentProvider().getComponent(), 250);
	}

	private void paste(final ClipboardContentProviderService clipboardService) {
		DockingWindowManager windowManager = DockingWindowManager.getActiveInstance();
		Window activeWindow = windowManager.getActiveWindow();
		Clipboard systemClipboard = getSystemClipboard();
		new TaskLauncher(new PasteTask(systemClipboard, clipboardService), activeWindow);
		clipboardOwnerProvider = null;
	}

	private void copySpecial(final ClipboardContentProviderService clipboardService,
			ClipboardType type, boolean prompt) {
		ClipboardType newType = type;

		List<ClipboardType> availableTypes = clipboardService.getCurrentCopyTypes();
		if (availableTypes == null || availableTypes.isEmpty()) {
			if (prompt) {
				Msg.showError(this, tool.getToolFrame(), "Error",
					"There are no copy formats available");
			}
			else {
				tool.setStatusInfo("There are no copy formats available");
			}
			return;
		}

		if (prompt) {
			final CopyPasteSpecialDialog dialog =
				new CopyPasteSpecialDialog(this, availableTypes, "Copy Special");
			tool.showDialog(dialog, clipboardService.getComponentProvider());
			newType = dialog.getSelectedType();
		}

		if (newType == null) {
			return;
		}

		lastUsedCopySpecialType.put(clipboardService, newType);
		final ClipboardType selectedType = newType;

		Task copyTask = new Task("Copying", true, false, true) {
			@Override
			public void run(TaskMonitor monitor) {
				monitor.setMessage("Setting Clipboard Contents");

				Clipboard systemClipboard = getSystemClipboard();
				Transferable transferable = clipboardService.copySpecial(selectedType, monitor);
				if (transferable != null) {
					setClipboardContents(systemClipboard, transferable);
					clipboardOwnerProvider = clipboardService;
					updatePasteState();
				}
			}
		};

		new TaskLauncher(copyTask, clipboardService.getComponentProvider().getComponent(), 250);
	}

	private Clipboard getSystemClipboard() {
		return GClipboard.getSystemClipboard();
	}

	void copySpecial(ClipboardContentProviderService clipboardService, ClipboardType type) {
		Clipboard systemClipboard = getSystemClipboard();
		Transferable transferable = clipboardService.copySpecial(type, TaskMonitor.DUMMY);
		if (transferable != null) {
			setClipboardContents(systemClipboard, transferable);
			updatePasteState();
		}
	}

	private static DataFlavor[] getAvailableDataFlavors(Clipboard clipboard) {
		try {
			return clipboard.getAvailableDataFlavors();
		}
		catch (Exception e) {
			// We catch any kind of problem here.  Some Linux distros have problems accessing 
			// the clipboard.
		}
		return new DataFlavor[0];
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private interface ICopy {
		// marker interface
	}

	private interface IPaste {
		// maker interface
	}

	private class CopyAction extends DockingAction implements ICopy {
		private final ClipboardContentProviderService clipboardService;

		private CopyAction(ClipboardContentProviderService clipboardService) {
			super("Copy", ClipboardPlugin.this.getName());
			this.clipboardService = clipboardService;

			setPopupMenuData(new MenuData(new String[] { "Copy" }, "Clipboard"));
			setToolBarData(new ToolBarData(ResourceManager.loadImage("images/page_white_copy.png"),
				"Clipboard"));
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK));
			setHelpLocation(new HelpLocation("ClipboardPlugin", "Copy"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			copy(clipboardService);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!clipboardService.isValidContext(context)) {
				return false;
			}
			return clipboardService.canCopy();
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof ListingActionContext || isEnabledForContext(context);
		}
	}

	private class PasteAction extends DockingAction implements IPaste {
		private final ClipboardContentProviderService clipboardService;

		private PasteAction(ClipboardContentProviderService clipboardService) {
			super("Paste", ClipboardPlugin.this.getName());
			this.clipboardService = clipboardService;

			setPopupMenuData(new MenuData(new String[] { "Paste" }, "Clipboard"));
			setToolBarData(
				new ToolBarData(ResourceManager.loadImage("images/page_paste.png"), "Clipboard"));
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK));
			setHelpLocation(new HelpLocation("ClipboardPlugin", "Paste"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			paste(clipboardService);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!clipboardService.isValidContext(context)) {
				return false;
			}

			Clipboard systemClipboard = getSystemClipboard();
			DataFlavor[] flavors = getAvailableDataFlavors(systemClipboard);
			return clipboardService.canPaste(flavors);
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof ListingActionContext || isEnabledForContext(context);
		}
	}

	private class CopySpecialAction extends DockingAction implements ICopy {
		private final ClipboardContentProviderService clipboardService;

		private CopySpecialAction(ClipboardContentProviderService clipboardService) {
			super("Copy Special", ClipboardPlugin.this.getName());
			this.clipboardService = clipboardService;

			setPopupMenuData(new MenuData(new String[] { "Copy Special..." }, "Clipboard"));
			setEnabled(false);
			setHelpLocation(new HelpLocation("ClipboardPlugin", "Copy_Special"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			copySpecial(clipboardService, null, true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!clipboardService.isValidContext(context)) {
				return false;
			}
			return clipboardService.canCopySpecial();
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return context instanceof ListingActionContext || isEnabledForContext(context);
		}
	}

	private class CopySpecialAgainAction extends DockingAction implements ICopy {
		private final ClipboardContentProviderService clipboardService;

		private CopySpecialAgainAction(ClipboardContentProviderService clipboardService) {
			super("Copy Special Again", ClipboardPlugin.this.getName());
			this.clipboardService = clipboardService;

			setPopupMenuData(new MenuData(new String[] { "Copy Special Again" }, "Clipboard"));
			setEnabled(false);
			setHelpLocation(new HelpLocation("ClipboardPlugin", "Copy_Special"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			copySpecial(clipboardService, lastUsedCopySpecialType.get(clipboardService), false);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!clipboardService.isValidContext(context)) {
				return false;
			}

			if (lastUsedCopySpecialType.get(clipboardService) == null) {
				return false;
			}

			String copiedItemName = lastUsedCopySpecialType.get(clipboardService).getTypeName();
			setPopupMenuData(
				new MenuData(new String[] { "Copy \"" + copiedItemName + "\"" }, "Clipboard"));
			return clipboardService.canCopySpecial();
		}
	}

	private static class DummyTransferable implements Transferable {

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			return null;
		}

		@Override
		public DataFlavor[] getTransferDataFlavors() {
			return new DataFlavor[0];
		}

		@Override
		public boolean isDataFlavorSupported(DataFlavor flavor) {
			return true;
		}

	}

	private static class PasteTask extends Task {

		private final Clipboard clipboard;
		private final ClipboardContentProviderService clipboardService;

		public PasteTask(Clipboard clipboard, ClipboardContentProviderService clipboardService) {
			super("Paste Task", false, false, true);
			this.clipboard = clipboard;
			this.clipboardService = clipboardService;
		}

		@Override
		public void run(TaskMonitor monitor) {
			Transferable transferable = clipboard.getContents(this);
			clipboardService.paste(transferable);
		}

	}
}
