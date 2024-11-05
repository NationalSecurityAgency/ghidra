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
package ghidra.app.plugin.core.debug.gui;

import java.awt.Component;
import java.beans.PropertyEditor;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.test.AbstractDockingTest;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.async.SwingExecutorService;
import ghidra.debug.api.ValStr;
import ghidra.framework.options.SaveState;

public class InvocationDialogHelper<P, D extends AbstractDebuggerParameterDialog<P>> {

	public static <P, D extends AbstractDebuggerParameterDialog<P>> InvocationDialogHelper<P, D> waitFor(
			Class<D> cls) {
		D dialog = AbstractDockingTest.waitForDialogComponent(cls);
		return new InvocationDialogHelper<>(dialog);
	}

	private final AbstractDebuggerParameterDialog<P> dialog;

	public InvocationDialogHelper(AbstractDebuggerParameterDialog<P> dialog) {
		this.dialog = dialog;
	}

	public void dismissWithArguments(Map<String, ValStr<?>> args) {
		dialog.setMemorizedArguments(args);
		invoke();
	}

	public <T> Map.Entry<String, ValStr<T>> entry(String key, T value) {
		return Map.entry(key, ValStr.from(value));
	}

	public void setArg(P param, Object value) {
		PropertyEditor editor = dialog.getEditor(param);
		runSwing(() -> editor.setValue(value));
	}

	public Component getEditorComponent(P param) {
		PropertyEditor editor = dialog.getEditor(param);
		return MiscellaneousUtils.getEditorComponent(editor);
	}

	protected void runSwing(Runnable r) {
		try {
			CompletableFuture.runAsync(r, SwingExecutorService.LATER).get();
		}
		catch (ExecutionException e) {
			switch (e.getCause()) {
				case RuntimeException t -> throw t;
				case Exception t -> throw new RuntimeException(t);
				default -> ExceptionUtils.rethrow(e.getCause());
			}
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public void setArgAsString(P param, String value) {
		PropertyEditor editor = dialog.getEditor(param);
		runSwing(() -> editor.setAsText(value));
	}

	public void invoke() {
		runSwing(() -> dialog.invoke(null));
	}

	public SaveState saveState() {
		SaveState parent = new SaveState();
		runSwing(() -> dialog.writeConfigState(parent));
		return parent.getSaveState(AbstractDebuggerParameterDialog.KEY_MEMORIZED_ARGUMENTS);
	}

	public void loadState(SaveState state) {
		SaveState parent = new SaveState();
		parent.putSaveState(AbstractDebuggerParameterDialog.KEY_MEMORIZED_ARGUMENTS, state);
		runSwing(() -> dialog.readConfigState(parent));
	}
}
