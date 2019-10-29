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

import java.io.File;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.*;

/**
 * Manages the threading involved with dealing with the decompiler. It uses a simpler approach
 * than previous versions.  Currently, there is only one Runnable ever scheduled to the RunManager.
 * If a new Decompile request comes in while a decompile is in progress, the new request is
 * first checked to see if it going to result in the same function being decompile. If so, then the
 * location is updated and the current decompile is allowed to continue.  If the new request is
 * a new function or the "forceDecompile" option is on, then the current decompile is stopped
 * and a new one is scheduled.  A SwingUpdateManger is used to prevent lots of decompile requests
 * from coming to quickly.
 *
 */
public class DecompilerManager {

	private DecompilerController decompilerController;
	private Decompiler decompiler;

	private DecompileRunnable currentDecompileRunnable;
	private DecompileRunnable pendingDecompileRunnable;
	private RunManager runManager;
	private SwingUpdateManager updateManager;

	public DecompilerManager(DecompilerController decompilerController, DecompileOptions options) {
		this.decompilerController = decompilerController;

		runManager = new RunManager("Decompiler", null);
		decompiler = new Decompiler(options, 0);

		updateManager = new SwingUpdateManager(500, () -> doPendingDecompile());
	}

	/**
	 * Set the decompiler options for future decompiles.
	 */
	void setOptions(DecompileOptions decompilerOptions) {
		decompiler.setOptions(decompilerOptions);
	}

	/**
	 * Returns the TaskMonitorComponent created by the RunManager and to be used in the
	 * DecompilerPanel.
	 */
	JComponent getTaskMonitorComponent() {
		return runManager.getMonitorComponent();
	}

	/**
	 * Resets the native decompiler process.  Call this method when the decompiler's view
	 * of a program has been invalidated, such as when a new overlay space has been added.
	 */
	public void resetDecompiler() {
		decompiler.resetDecompiler();
	}

	/**
	 * Requests a new decompile be scheduled.  If a current decompile is already in progress,
	 * the new request is checked to see if represents the same function. If so, only the
	 * location of the current decompile is updated and the current decompile is allowed to continue.
	 * Otherwise a new DecompileRunnable is created and scheduled to run using the updateManager.
	 * When the updateMangers runs, it will stop any current decompiles and begin the new decompile.
	 * @param program The program containing the function to be decompiled.
	 * @param location the location in the program to be decompiled and positioned to.
	 * @param debugFile if non-null, creates decompile debug output to this file.
	 * @param forceDecompile true forces a new decompile to be scheduled even if the current job
	 * is the same function.
	 */
	synchronized void decompile(Program program, ProgramLocation location,
			ViewerPosition viewerPosition, File debugFile, boolean forceDecompile) {

		DecompileRunnable newDecompileRunnable =
			new DecompileRunnable(program, location, debugFile, viewerPosition, this);

		if (forceDecompile) {
			cancelAll();
			setPendingRunnable(newDecompileRunnable);
			return;
		}

		if (updateCurrentRunnable(newDecompileRunnable)) {
			return;
		}

		setPendingRunnable(newDecompileRunnable);
	}

	private synchronized void setPendingRunnable(DecompileRunnable newDecompileRunnable) {
		pendingDecompileRunnable = newDecompileRunnable;
		updateManager.update();
	}

	private synchronized boolean updateCurrentRunnable(DecompileRunnable newDecompileRunnable) {
		if (pendingDecompileRunnable != null) {
			return false; // can't update when pending
		}

		if (currentDecompileRunnable == null) {
			return false; // nothing to update
		}

		return currentDecompileRunnable.update(newDecompileRunnable);
	}

	public synchronized boolean isBusy() {
		return currentDecompileRunnable != null || pendingDecompileRunnable != null;
	}

	public synchronized void cancelAll() {
		cancelCurrentRunnable();
		pendingDecompileRunnable = null;
	}

	private synchronized void cancelCurrentRunnable() {
		if (currentDecompileRunnable != null) {
			runManager.cancelAllRunnables();
			decompiler.cancelCurrentAction();
			currentDecompileRunnable = null;
		}
	}

	public void dispose() {
		updateManager.dispose();
		runManager.dispose();
		cancelAll();
		decompiler.dispose();
	}

	private synchronized void doPendingDecompile() {
		if (pendingDecompileRunnable == null) {
			return; // somebody cleared the pending update
		}

		cancelCurrentRunnable();

		currentDecompileRunnable = pendingDecompileRunnable;
		pendingDecompileRunnable = null;

		decompilerController.decompilerStatusChanged();
		runManager.runNow(currentDecompileRunnable, "Decompiler", 500);
	}

//==================================================================================================
// DecompileRunnable methods
//==================================================================================================

	DecompileResults decompile(Program program, Function functionToDecompile, File debugFile,
			TaskMonitor monitor) throws DecompileException {

		return decompiler.decompile(program, functionToDecompile, debugFile, monitor);

	}

	void setDecompileData(DecompileRunnable runnable, DecompileData decompileData) {

		if (decompilerController == null) {
			return; // disposed!
		}

		synchronized (this) {
			if (currentDecompileRunnable != runnable) {
				return; // a new request has come in, ignore these outdated results
			}

			currentDecompileRunnable = null;
		}

		decompilerController.setDecompileData(decompileData);
	}

}
