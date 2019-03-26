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
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.GhidraOptions;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.programtree.ViewManagerComponentProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.listingpanel.MarginProvider;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class BlockModelScreenShots extends GhidraScreenShotGenerator {

	public BlockModelScreenShots() {
		super();
	}

	@Test
	public void testBasicBlockCode() throws Exception {

		closeProvider(DataTypesProvider.class);
		closeProvider(ViewManagerComponentProvider.class);

		disableFlowArrows();
		createMinimalFormat();
		enlargeFont();

		AddressSet addressSet = new AddressSet();
		addressSet.addRange(addr(0x004074c6), addr(0x004074fa).subtract(1));

		restrictView(addressSet);
		highlightCodeBlocks(addressSet);

		//crop just the needed fields and pad the image
		goToListing(0x0401de0);
		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		ListingPanel lp = cb.getListingPanel();

		Dimension size = lp.getPreferredSize();
		final Window window = windowForComponent(lp);
		runSwing(() -> {
			Point p = window.getLocation();
			p.y = 50;
			window.setLocation(p);
		});

		setWindowSize(window, size.width, 970);
		captureComponent(lp);

	}

	private void restrictView(final AddressSet addressSet) {
		runSwing(() -> {
			CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
			ListingPanel lp = cb.getListingPanel();
			lp.setView(addressSet);
			lp.setNeverSroll();
		});
	}

	private void highlightCodeBlocks(final AddressSet addressSet) {
		int tx = program.startTransaction("Test");
		runSwing(() -> {

			ColorizingService colorizer = tool.getService(ColorizingService.class);

			Color c1 = new Color(0xE8F2FE);

			Color c2 = new Color(170, 204, 245);
			Color color = c1;

			BasicBlockModel basicBlockModel = new BasicBlockModel(program);
			CodeBlockIterator iterator;
			try {
				iterator = basicBlockModel.getCodeBlocksContaining(addressSet,
					TaskMonitorAdapter.DUMMY_MONITOR);

				while (iterator.hasNext()) {
					CodeBlock block = iterator.next();
					Address min = block.getMinAddress();
					Address max = block.getMaxAddress();
					colorizer.setBackgroundColor(min, max, color);
					color = (color == c1) ? c2 : c1;
				}
			}
			catch (CancelledException e) {
				// can't happen--dummy monitor
			}
		});
		program.endTransaction(tx, true);

		waitForSwing();
	}

	private void enlargeFont() {
		runSwing(() -> {
			Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
			Font font = options.getFont(GhidraOptions.OPTION_BASE_FONT, null);
			options.setFont(GhidraOptions.OPTION_BASE_FONT, font.deriveFont(18f));
		});
	}

	private void disableFlowArrows() {

		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		final ListingPanel lp = cb.getListingPanel();

		@SuppressWarnings("unchecked")
		final List<MarginProvider> list =
			new ArrayList<>((List<MarginProvider>) getInstanceField("marginProviders", lp));
		runSwing(() -> {
			invokeInstanceMethod("buildPanels", lp);
			for (MarginProvider marginProvider : list) {
				lp.removeMarginProvider(marginProvider);
			}
		});
	}

	private ListingPanel createMinimalFormat() {
		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		final ListingPanel lp = cb.getListingPanel();
		runSwing(() -> {
			FormatManager newFormat = createFormat();
			lp.setFormatManager(newFormat);
		});
		return lp;
	}

	private FormatManager createFormat() {
		OptionsService options = tool.getService(OptionsService.class);
		ToolOptions displayOptions = options.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		ToolOptions fieldOptions = options.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);

		FormatManager manager = new FormatManager(displayOptions, fieldOptions);
		for (int i = 0; i < manager.getNumModels(); i++) {
			FieldFormatModel formatModel = manager.getModel(i);
			int numRows = formatModel.getNumRows();
			for (int row = 0; row < numRows; row++) {
				FieldFactory[] allRowFactories = formatModel.getFactorys(row);
				for (int col = allRowFactories.length - 1; col >= 0; col--) {
					FieldFactory fieldFactory = allRowFactories[col];

//					Msg.debug(this, "checking factory: " + fieldFactory.getFieldName());

					if (fieldFactory.getFieldName().indexOf("XRef") != -1) {
						formatModel.removeFactory(row, col);
					}
					else if (fieldFactory.getFieldName().equals(
						EolCommentFieldFactory.FIELD_NAME)) {
						formatModel.removeFactory(row, col);
					}
					else if (fieldFactory.getFieldName().equals(AddressFieldFactory.FIELD_NAME)) {
						fieldFactory.setWidth(fieldFactory.getWidth() + 25);
						formatModel.updateRow(row);
					}
					else if (fieldFactory.getFieldName().equals(OperandFieldFactory.FIELD_NAME)) {
						fieldFactory.setWidth(fieldFactory.getWidth() + 25);
						formatModel.updateRow(row);
					}
				}
			}
		}

		for (int i = 0; i < manager.getNumModels(); i++) {
			FieldFormatModel codeUnitFormat = manager.getModel(i);
			int numRows = codeUnitFormat.getNumRows();
			for (int j = numRows - 1; j >= 0; j--) {
				FieldFactory[] allRowFactories = codeUnitFormat.getFactorys(j);
				if (allRowFactories.length == 0) {
					codeUnitFormat.removeRow(j);
				}
			}
		}

		return manager;
	}
}
