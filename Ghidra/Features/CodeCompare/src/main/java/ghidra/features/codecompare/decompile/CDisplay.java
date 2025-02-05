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
package ghidra.features.codecompare.decompile;

import java.math.BigInteger;
import java.util.function.Consumer;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Represents one side of a dual decompiler compare window. It holds the decompiler controller and
 * related state information for one side. 
 */
public class CDisplay {
	private final static String OPTIONS_TITLE = "Decompiler";

	private ServiceProvider serviceProvider;
	private DecompilerController controller;
	private DecompileOptions decompileOptions;
	private FieldLocation lastCursorPosition;
	private DiffClangHighlightController highlightController;
	private Program program;

	private DecompilerProgramListener programListener;

	public CDisplay(ServiceProvider serviceProvider,
			DecompilerCodeComparisonOptions comparisonOptions,
			DecompileResultsListener decompileListener,
			Consumer<ProgramLocation> locationConsumer) {

		this.serviceProvider = serviceProvider;
		highlightController = new DiffClangHighlightController(comparisonOptions);

		decompileOptions = new DecompileOptions();

		DecompilerCallbackHandler handler = new DecompilerCallbackHandlerAdapter() {
			@Override
			public void locationChanged(ProgramLocation programLocation) {
				locationConsumer.accept(programLocation);
			}
		};

		controller = new DecompilerController(serviceProvider, handler, decompileOptions, null) {
			@Override
			public void setDecompileData(DecompileData decompileData) {
				super.setDecompileData(decompileData);
				decompileListener.setDecompileData(decompileData);
				controller.getDecompilerPanel().validate();
			}
		};
		controller.getDecompilerPanel().setHighlightController(highlightController);

		programListener = new DecompilerProgramListener(controller, () -> refresh());

	}

	public DecompilerPanel getDecompilerPanel() {
		return controller.getDecompilerPanel();
	}

	private void updateProgram(PluginTool tool, Function function) {
		Program newProgram = function == null ? null : function.getProgram();
		if (program == newProgram) {
			return;
		}
		if (program != null) {
			program.removeListener(programListener);
		}

		program = newProgram;

		if (program != null) {
			program.addListener(programListener);
			initializeOptions(tool, function);
		}

	}

	public void showFunction(PluginTool tool, Function function) {
		updateProgram(tool, function);

		lastCursorPosition = null;
		if (function == null) {
			clearAndShowMessage("No Function");
			return;
		}
		if (function.isExternal()) {
			clearAndShowMessage("\"" + function.getName(true) + "\" is an external function.");
			return;
		}

		Address entry = function.getEntryPoint();
		ProgramLocation location = new ProgramLocation(program, entry);
		controller.display(program, location, new ViewerPosition(0, 0, 0));
	}

	public void clearAndShowMessage(String message) {
		controller.setDecompileData(new EmptyDecompileData(message));
		DecompilerPanel decompilerPanel = getDecompilerPanel();
		decompilerPanel.paintImmediately(decompilerPanel.getBounds());
	}

	public void setMouseNavigationEnabled(boolean enabled) {
		controller.setMouseNavigationEnabled(enabled);
	}

	public void dispose() {
		if (program != null) {
			program.removeListener(programListener);
			program = null;
		}
		programListener.dispose();
		controller.dispose();
	}

	public DecompilerController getController() {
		return controller;
	}

	public void refresh() {
		saveCursorPosition();
		DecompileData data = getDecompileData();
		if (data != null) {
			controller.refreshDisplay(data.getProgram(), data.getLocation(), null);
		}
	}

	public void programClosed(Program closedProgram) {
		if (closedProgram == this.program) {
			controller.clear();
			controller.programClosed(closedProgram);
			updateProgram(null, null);
		}
	}

	public boolean isBusy() {
		return controller.isDecompiling();
	}

	public DecompileData getDecompileData() {
		DecompileData decompileData = controller.getDecompileData();
		if (decompileData instanceof EmptyDecompileData) {
			return null;
		}
		return decompileData;
	}

	public void initializeOptions(PluginTool tool, Function function) {
		if (tool == null) {
			return;
		}
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		ToolOptions options = tool.getOptions(OPTIONS_TITLE);
		Program program = function == null ? null : function.getProgram();
		decompileOptions.grabFromToolAndProgram(fieldOptions, options, program);
	}

	DiffClangHighlightController getHighlightController() {
		return highlightController;
	}

	private void saveCursorPosition() {
		lastCursorPosition = getDecompilerPanel().getFieldPanel().getCursorLocation();
	}

	void restoreCursorPosition() {
		if (lastCursorPosition != null) {
			BigInteger index = lastCursorPosition.getIndex();
			int fieldNum = lastCursorPosition.getFieldNum();
			int row = lastCursorPosition.getRow();
			int col = lastCursorPosition.getCol();

			FieldPanel fieldPanel = getDecompilerPanel().getFieldPanel();
			fieldPanel.setCursorPosition(index, fieldNum, row, col);
		}
	}

}
