/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.task;

import ghidra.util.Msg;

import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

/**
 * A task that will simply invoke the given runnable later in the Swing thread.  This class is
 * useful for executing long running tasks in the swing thread while using the 
 * {@link TaskLauncher} to show a modal dialog.
 */
public class InvokeInSwingTask extends Task {

    private final Runnable runnable;

    public InvokeInSwingTask( String title, Runnable runnable ) {
        super( title, false, false, true );
        this.runnable = runnable;
    }

    @Override
    public void run( TaskMonitor monitor ) {
        try {
			SwingUtilities.invokeAndWait( runnable );
		} catch (InterruptedException e) {
			Msg.showError(runnable, null, "Task Error", "Task interrupted: " + getTaskTitle(), e);
		} catch (InvocationTargetException e) {
			Msg.showError(runnable, null, "Task Error", "Unexpected task exception: " + getTaskTitle(), e);
		}
    }

}
