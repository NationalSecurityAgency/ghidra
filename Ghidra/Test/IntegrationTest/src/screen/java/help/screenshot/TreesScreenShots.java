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
import java.util.Arrays;

import javax.swing.*;
import javax.swing.table.JTableHeader;

import org.junit.Test;

import docking.DockableComponent;
import docking.menu.MultiStateDockingAction;
import docking.util.AnimationUtils;
import docking.util.image.Callout;
import docking.util.image.CalloutComponentInfo;
import docking.widgets.EmptyBorderButton;
import docking.widgets.filter.*;
import docking.widgets.table.columnfilter.ColumnBasedTableFilter;
import docking.widgets.table.columnfilter.LogicOperation;
import docking.widgets.table.constraint.*;
import docking.widgets.table.constraint.provider.EditorProvider;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;
import docking.widgets.table.constrainteditor.IntegerConstraintEditor;
import docking.widgets.table.threaded.ThreadedTableModel;
import docking.widgets.tree.*;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.functionwindow.FunctionWindowProvider;
import ghidra.program.model.listing.Function;
import ghidra.util.table.GhidraTableFilterPanel;

public class TreesScreenShots extends GhidraScreenShotGenerator {

	@Override
	public void setUp() throws Exception {
		super.setUp();
		AnimationUtils.setAnimationEnabled(false);
		closeNonProgramArchives();
	}

	@Test
	public void testFilter() {

		setTreeFilterText("byte");

		captureIsolatedProvider(DataTypesProvider.class, 375, 350);
	}

	@Test
	public void testFilterClearButton() {

		setTreeFilterText("byte");

		captureIsolatedProvider(DataTypesProvider.class, 375, 350);

		calloutFilterIcon();

		cropAndKeepFilter();
	}

	private void calloutFilterIcon() {

		DataTypesProvider provider = getProvider(DataTypesProvider.class);
		DataTypeArchiveGTree gTree = provider.getGTree();
		GTreeFilterProvider filterProvider = gTree.getFilterProvider();
		FilterTextField field = (FilterTextField) getInstanceField("filterField", filterProvider);
		JLabel label = (JLabel) getInstanceField("clearLabel", field);

		/*
		 	The callout needs to know where to paint the callout.   We want it over the
		 	component we provide.   But, we need to be able to translate that component's
		 	location to a value that is relative to the image (we created the image above by
		 	capturing the provider using it's DockableComponent).
		 */

		DockableComponent dc = getDockableComponent(provider);

		CalloutComponentInfo calloutInfo = new CalloutComponentInfo(dc, label);
		calloutInfo.setMagnification(2.75D); // make it a bit bigger than default
		Callout callout = new Callout();
		image = callout.createCalloutOnImage(image, calloutInfo);
	}

	private void cropAndKeepFilter() {

		// keep the filter and callout in the image (trial and error)
		Rectangle area = new Rectangle();
		int height = 275;
		area.x = 0;
		area.y = 80;
		area.width = 560;
		area.height = height - area.y;
		crop(area);
	}

	@Test
	public void testTableColumnFilter() {
		showProvider(FunctionWindowProvider.class);
		captureIsolatedProvider(FunctionWindowProvider.class, 600, 300);
	}

	@Test
	public void testTableColumnFilterDialog() {
		showProvider(FunctionWindowProvider.class);
		FunctionWindowProvider provider = getProvider(FunctionWindowProvider.class);
		@SuppressWarnings({ "unchecked" })
		GhidraTableFilterPanel<Function> panel =
			(GhidraTableFilterPanel<Function>) getInstanceField("tableFilterPanel", provider);
		ColumnBasedTableFilter<Function> filter =
			new ColumnBasedTableFilter<>(panel.getTableFilterModel());
		filter.addConstraintSet(LogicOperation.AND, 0,
			Arrays.asList(new StringStartsWithColumnConstraint("FUN_00"),
				new StringContainsColumnConstraint("401")));
		filter.addConstraintSet(LogicOperation.AND, 3,
			Arrays.asList(new AtLeastColumnConstraint<>(80, new IntEditorProvider())));
		panel.setColumnTableFilter(filter);
		MultiStateDockingAction<?> action =
			(MultiStateDockingAction<?>) getInstanceField("columnFilterAction", panel);
		performAction(action, false);
		captureDialog(1000, 400);
	}

	@Test
	@SuppressWarnings({ "unchecked" })
	public void testTableColumnFilterAfterFilterApplied() {
		showProvider(FunctionWindowProvider.class);
		FunctionWindowProvider provider = getProvider(FunctionWindowProvider.class);

		GhidraTableFilterPanel<Function> panel =
			(GhidraTableFilterPanel<Function>) getInstanceField("tableFilterPanel", provider);

		ColumnBasedTableFilter<Function> filter =
			new ColumnBasedTableFilter<>(panel.getTableFilterModel());
		filter.addConstraintSet(LogicOperation.AND, 0,
			Arrays.asList(new StringStartsWithColumnConstraint("FUN_00"),
				new StringContainsColumnConstraint("401")));
		filter.addConstraintSet(LogicOperation.AND, 3,
			Arrays.asList(new AtLeastColumnConstraint<>(80, new IntEditorProvider())));
		panel.setColumnTableFilter(filter);

		JTable table = (JTable) invokeInstanceMethod("getTable", panel);
		waitForTableModel((ThreadedTableModel<?, ?>) table.getModel());

		captureIsolatedProvider(FunctionWindowProvider.class, 600, 300);

		JTableHeader header = table.getTableHeader();

		// we are filtered on 0 and 3
		highlightFilterIcon(provider.getComponent(), table, header, 0);
		highlightFilterIcon(provider.getComponent(), table, header, 3);

	}

	private void highlightFilterIcon(Component provider, Component parent, JTableHeader header,
			int column) {

		Rectangle rectangle = header.getHeaderRect(column);
		rectangle = SwingUtilities.convertRectangle(parent, rectangle, provider);

		int padding = 8;
		int thickness = 6;
		int iconSize = 12;
		int height = rectangle.height + (padding * 2);
		int width = iconSize + (padding * 2);

		int iconPadding = 2;
		int x = rectangle.x + rectangle.width - (width - padding) - iconPadding;
		int y = rectangle.y - padding;
		Rectangle shapeBounds = new Rectangle(x, y, width, height);
		drawOval(Color.GREEN.darker(), shapeBounds, thickness);

	}

	@Test
	public void testFilterOptions() {

		DataTypesProvider dataTypeManagerProvider = getProvider(DataTypesProvider.class);

		DataTypeArchiveGTree gTree = dataTypeManagerProvider.getGTree();

		GTreeFilterProvider filterProvider = gTree.getFilterProvider();

		((DefaultGTreeFilterProvider) filterProvider).setFilterOptions(
			new FilterOptions(TextFilterStrategy.CONTAINS, true, false, false, true, ','));

		EmptyBorderButton filterButton =
			(EmptyBorderButton) getInstanceField("filterStateButton", filterProvider);
		pressButton(filterButton, false);

		captureDialog();
	}

	private void setTreeFilterText(final String text) {

		final DataTypesProvider dataTypeManagerProvider = getProvider(DataTypesProvider.class);

		runSwing(() -> dataTypeManagerProvider.setFilterText(text));

		GTree tree = (GTree) getInstanceField("archiveGTree", dataTypeManagerProvider);
		waitForTree(tree);

		scrollTreeToTop(tree);
	}

	private void scrollTreeToTop(GTree tree) {
		JScrollPane scrollPane = (JScrollPane) getInstanceField("scrollPane", tree);
		runSwing(() -> scrollPane.getVerticalScrollBar().setValue(0));
	}

	static class IntEditorProvider implements EditorProvider<Integer> {

		@Override
		public ColumnConstraintEditor<Integer> getEditor(ColumnConstraint<Integer> columnConstraint,
				ColumnData<Integer> columnDataSource) {
			return new IntegerConstraintEditor<>(columnConstraint, v -> (int) v);
		}

		@Override
		public Integer parseValue(String value, Object dataSource) {
			return (int) Long.parseLong(value);
		}

		@Override
		public String toString(Integer value) {
			return value.toString();
		}
	}
}
