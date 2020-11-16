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
package ghidra.app.decompiler.component;

import java.awt.event.MouseEvent;
import java.io.File;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.DecompilerClipboardProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import utility.function.Callback;

/**
 * Coordinates the interactions between the DecompilerProvider, DecompilerPanel, and the DecompilerManager
 */

public class DecompilerController {
	private DecompilerPanel decompilerPanel;
	private DecompilerManager decompilerMgr;
	private final DecompilerCallbackHandler callbackHandler;
	private DecompileData currentDecompileData;
	private ProgramSelection currentSelection;
	private Cache<Function, DecompileResults> decompilerCache;
	private int cacheSize;

	public DecompilerController(DecompilerCallbackHandler handler, DecompileOptions options,
			DecompilerClipboardProvider clipboard) {
		this.cacheSize = options.getCacheSize();
		this.callbackHandler = handler;
		decompilerCache = buildCache();
		decompilerMgr = new DecompilerManager(this, options);
		decompilerPanel =
			new DecompilerPanel(this, options, clipboard, decompilerMgr.getTaskMonitorComponent());

		decompilerPanel.setHoverMode(true);

	}

	public DecompilerPanel getDecompilerPanel() {
		return decompilerPanel;
	}

//==================================================================================================
//  Methods call by the provider
//==================================================================================================
	/**
	 * Called by the provider when the provider is disposed.  Once dispose is called, it should
	 * never be used again.
	 */
	public void dispose() {
		clearCache();
		decompilerMgr.dispose();
		decompilerPanel.dispose();
	}

	/**
	 * clears all internal state and releases all resources.  Called when the provider is no
	 * longer visible or the currently displayed program is closed.
	 */
	public void clear() {
		currentSelection = null;
		decompilerMgr.cancelAll();
		setDecompileData(new EmptyDecompileData("No Function"));
	}

	/**
	 * Shows the function containing the given location in the decompilerPanel.  Also, positions the
	 * decompilerPanel's cursor to the closest equivalent position. If the decompilerPanel is
	 * already displaying the function, then only the cursor is repositioned.  To force a
	 * re-decompile use {@link #refreshDisplay(Program, ProgramLocation, File)}.
	 *
	 * @param program the program for the given location
	 * @param location the location containing the function to be displayed and the location in
	 * that function to position the cursor.
	 * @param viewerPosition the viewer position
	 */
	public void display(Program program, ProgramLocation location, ViewerPosition viewerPosition) {
		if (!decompilerMgr.isBusy() && decompilerPanel.containsLocation(location)) {
			decompilerPanel.setLocation(location, viewerPosition);
			return;
		}

		if (loadFromCache(program, location, viewerPosition)) {
			decompilerPanel.setLocation(location, viewerPosition);
			return;
		}
		decompilerMgr.decompile(program, location, viewerPosition, null, false);
	}

	private boolean loadFromCache(Program program, ProgramLocation location,
			ViewerPosition viewerPosition) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(location.getAddress());

		if (function == null) { // cache can't handle null keys
			return false;
		}

		DecompileResults results = decompilerCache.getIfPresent(function);
		if (results == null) {
			return false;
		}

		// cancel pending decompile tasks; previous requests shouldn't overwrite the latest request
		decompilerMgr.cancelAll();
		setDecompileData(
			new DecompileData(program, function, location, results, null, null, viewerPosition));

		return true;
	}

	public void setSelection(ProgramSelection selection) {
		decompilerPanel.setSelection(selection);
	}

	/**
	 * Sets new decompiler options and triggers a new decompile.
	 * @param decompilerOptions the options
	 */
	public void setOptions(DecompileOptions decompilerOptions) {
		clearCache();
		if (decompilerOptions.getCacheSize() != cacheSize) {
			cacheSize = decompilerOptions.getCacheSize();
			decompilerCache = buildCache();
		}
		decompilerMgr.setOptions(decompilerOptions);
		decompilerPanel.optionsChanged(decompilerOptions);
	}

	public boolean isDecompiling() {
		return decompilerMgr.isBusy();
	}

	public void setMouseNavigationEnabled(boolean enabled) {
		decompilerPanel.setMouseNavigationEnabled(enabled);
	}

	/**
	 * Resets the native decompiler process.  Call this method when the decompiler's view
	 * of a program has been invalidated, such as when a new overlay space has been added.
	 */
	public void resetDecompiler() {
		decompilerMgr.resetDecompiler();
	}

//==================================================================================================
//  Methods call by the DecompilerManager
//==================================================================================================

	/**
	 * Called by the DecompilerManager to update the currently displayed DecompileData
	 * @param decompileData the new data
	 */
	public void setDecompileData(DecompileData decompileData) {
		updateCache(decompileData);
		currentDecompileData = decompileData;
		decompilerPanel.setDecompileData(decompileData);
		decompilerPanel.setSelection(currentSelection);
		callbackHandler.decompileDataChanged(decompileData);
	}

	private void updateCache(DecompileData decompileData) {
		Function function = decompileData.getFunction();
		DecompileResults results = decompileData.getDecompileResults();
		if (function != null && results != null && results.decompileCompleted()) {
			decompilerCache.put(function, results);
		}
	}

	void decompilerStatusChanged() {
		callbackHandler.contextChanged();
	}

//==================================================================================================
//  Methods called by actions and other miscellaneous classes
//==================================================================================================

	public void doWhenNotBusy(Callback c) {
		callbackHandler.doWheNotBusy(c);
	}

	/**
	 * Always decompiles the function containing the given location before positioning the
	 * decompilerPanel's cursor to the closest equivalent position.
	 * @param program the program for the given location
	 * @param location the location containing the function to be displayed and the location in
	 * that function to position the cursor.
	 * @param debugFile the debug file
	 */
	public void refreshDisplay(Program program, ProgramLocation location, File debugFile) {
		clearCache();
		decompilerMgr.decompile(program, location, null, debugFile, true);
	}

	public boolean hasDecompileResults() {
		if (currentDecompileData != null) {
			return currentDecompileData.hasDecompileResults();
		}
		return false;
	}

	public ClangTokenGroup getCCodeModel() {
		return currentDecompileData.getCCodeMarkup();
	}

	public void setStatusMessage(String message) {
		callbackHandler.setStatusMessage(message);
	}

	public Program getProgram() {
		if (currentDecompileData != null) {
			return currentDecompileData.getProgram();
		}
		return null;
	}

	public Function getFunction() {
		if (currentDecompileData != null) {
			return currentDecompileData.getFunction();
		}
		return null;
	}

	public HighFunction getHighFunction() {
		if (currentDecompileData != null) {
			return currentDecompileData.getHighFunction();
		}
		return null;
	}

	public ProgramLocation getLocation() {
		if (currentDecompileData != null) {
			return currentDecompileData.getLocation();
		}
		return null;
	}

	void locationChanged(ProgramLocation programLocation) {
		callbackHandler.locationChanged(programLocation);
	}

	void selectionChanged(ProgramSelection programSelection) {
		currentSelection = programSelection;
		callbackHandler.selectionChanged(programSelection);
	}

	void annotationClicked(AnnotatedTextFieldElement annotation, MouseEvent event,
			boolean newWindow) {
		callbackHandler.annotationClicked(annotation, newWindow);
	}

	void goToFunction(Function function, boolean newWindow) {
		Function thunkedFunction = function.getThunkedFunction(true);
		if (thunkedFunction != null) {
			function = thunkedFunction;
		}
		callbackHandler.goToFunction(function, newWindow);
	}

	void goToLabel(String labelName, boolean newWindow) {
		callbackHandler.goToLabel(labelName, newWindow);
	}

	void goToAddress(Address addr, boolean newWindow) {
		callbackHandler.goToAddress(addr, newWindow);
	}

	void goToScalar(long value, boolean newWindow) {
		callbackHandler.goToScalar(value, newWindow);
	}

	public DecompileData getDecompileData() {
		return currentDecompileData;
	}

	public void exportLocation() {
		callbackHandler.exportLocation();
	}

	private Cache<Function, DecompileResults> buildCache() {
		//@formatter:off
		return CacheBuilder.newBuilder()
		                   .softValues()
			               .maximumSize(cacheSize)
			               .build();
		//@formatter:on
	}

	public void clearCache() {
		decompilerCache.invalidateAll();
	}

	public void programClosed(Program closedProgram) {
		for (Function function : decompilerCache.asMap().keySet()) {
			Program functionProgram = function.getProgram();
			if (functionProgram == closedProgram) {
				decompilerCache.invalidate(function);
			}
		}
	}
}
