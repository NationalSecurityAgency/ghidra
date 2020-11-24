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
package help.screenshot;

import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.*;

import org.junit.Test;

import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.FieldPanel;
import ghidra.app.plugin.core.clipboard.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.util.viewer.field.MnemonicFieldFactory;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

public class ClipboardPluginScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testCaptureCopySpecial() {

		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		ProgramSelection sel = cb.getCurrentSelection();
		Msg.debug(this, "selection: " + sel);

		makeSelection(0x401000, 0x401000);

		sel = cb.getCurrentSelection();

		CopyPasteSpecialDialog dialog = showCopySpecialDialog();
		Window window = SwingUtilities.windowForComponent(dialog.getComponent());

		Dimension size = window.getSize();
		setWindowSize(window, size.width, 330);
		captureDialog();
	}

	@Test
	public void testCaptureCopySpecialAgain() {
		long start = 0x406604;
		long end = 0x40660d;
		makeSelection(start, end);
		copySpecialLabelsAndComments();
		waitForSwing();

		showCopyMenu();
		captureMenu();
		cropCopyMenu();
		Image menuImage = image;

		captureListingCallMnemonic(start, end);

		placeImagesSideBySide(image, menuImage);
		drawBorder(Color.BLACK);
	}

	private void cropCopyMenu() {
		JPopupMenu popupMenu = getPopupMenu();
		MenuElement[] elements = popupMenu.getSubElements();

		//
		// we expect the following menu items in order:
		// -Copy
		// -Copy Special
		// -Copy "Labels and Comments"
		// -Paste
		//
		int index = -1;
		int n = elements.length;
		for (int i = 0; i < n; i++) {
			JMenuItem item = (JMenuItem) elements[i];
			String text = item.getText();
			if ("Copy".equals(text)) {
				// found it!
				index = i;
				break;
			}
		}

		if (index == -1) {
			throw new AssertException("Couldn't find copy menu item");
		}

		Rectangle copySectionBounds = new Rectangle();
		int height = 0;
		JMenuItem item = (JMenuItem) elements[index];
		Rectangle itemBounds = item.getBounds();

		copySectionBounds.x = itemBounds.x;
		copySectionBounds.y = itemBounds.y;
		copySectionBounds.width = itemBounds.width;
		height += itemBounds.height;

		item = (JMenuItem) elements[index + 1];
		itemBounds = item.getBounds();
		height += itemBounds.height;

		item = (JMenuItem) elements[index + 2];
		itemBounds = item.getBounds();
		height += itemBounds.height;

		item = (JMenuItem) elements[index + 3];
		itemBounds = item.getBounds();
		height += itemBounds.height;

		copySectionBounds.height = height;

		crop(copySectionBounds);
	}

	private void showCopyMenu() {
		long addr = 0x406606;
		positionListingCenter(addr);
		positionCursor(addr, MnemonicFieldFactory.FIELD_NAME);
		rightClickCursor();
	}

	private void copySpecialLabelsAndComments() {
		showCopySpecialDialog();
		selectLabelsAndComments();
		pressOkOnDialog();
	}

	private void selectLabelsAndComments() {
		DialogComponentProvider copySpecialDialog = getDialog(CopyPasteSpecialDialog.class);

		Object listPanel = getInstanceField("listPanel", copySpecialDialog);
		final JList<?> list = (JList<?>) getInstanceField("list", listPanel);
		runSwing(new Runnable() {
			@Override
			public void run() {
				ListModel<?> model = list.getModel();
				int size = model.getSize();
				for (int i = 0; i < size; i++) {
					Object value = model.getElementAt(i);
					if ("Labels and Comments".equals(value.toString())) {
						list.setSelectedIndex(i);
						return;
					}
				}

				throw new RuntimeException("Could not find 'Labels and Comments' copy action");
			}
		});
		waitForSwing();
	}

	private void captureListingCallMnemonic(long start, long end) {
		captureListingRange(start, end, 500);

		Rectangle imageBounds = new Rectangle();

		positionCursor(0x406606, MnemonicFieldFactory.FIELD_NAME);
		Rectangle cursorBounds = getCursorBounds();

		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		FieldPanel fieldPanel = plugin.getFieldPanel();
		CodeViewerProvider provider = plugin.getProvider();
		cursorBounds.setLocation(SwingUtilities.convertPoint(fieldPanel, cursorBounds.getLocation(),
			provider.getListingPanel()));

		imageBounds.x = cursorBounds.x - 30; // move back some
		imageBounds.y = cursorBounds.y - 30; // move up some to get the previous instruction
		imageBounds.width = 100;
		imageBounds.height = image.getHeight(null);
		crop(imageBounds);
	}

	private CopyPasteSpecialDialog showCopySpecialDialog() {
		ClipboardPlugin plugin = getPlugin(tool, ClipboardPlugin.class);
		ClipboardContentProviderService service = getClipboardService(plugin);
		DockingActionIf pasteAction = getLocalAction(service, "Copy Special", plugin);
		performAction(pasteAction, false);
		return waitForDialogComponent(CopyPasteSpecialDialog.class);
	}

	private ClipboardContentProviderService getClipboardService(
			ClipboardPlugin clipboardPlugin) {
		Map<?, ?> serviceMap = (Map<?, ?>) getInstanceField("serviceActionMap", clipboardPlugin);
		Set<?> keySet = serviceMap.keySet();
		for (Object name : keySet) {
			ClipboardContentProviderService service = (ClipboardContentProviderService) name;
			if (service.getClass().equals(CodeBrowserClipboardProvider.class)) {
				return service;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private DockingAction getLocalAction(ClipboardContentProviderService service, String actionName,
			ClipboardPlugin clipboardPlugin) {
		Map<?, ?> actionsByService =
			(Map<?, ?>) getInstanceField("serviceActionMap", clipboardPlugin);
		List<DockingAction> actionList = (List<DockingAction>) actionsByService.get(service);
		for (DockingAction pluginAction : actionList) {
			if (pluginAction.getName().equals(actionName)) {
				return pluginAction;
			}
		}

		return null;
	}
}
