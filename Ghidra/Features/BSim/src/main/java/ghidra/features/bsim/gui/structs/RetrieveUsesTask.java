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
package ghidra.features.bsim.gui.structs;

import java.util.*;

import ghidra.app.plugin.core.navigation.locationreferences.LocationReference;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.FieldMatcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.SetAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class RetrieveUsesTask extends Task {

	private StructureRecoveryPlugin plugin;
	private Structure targetDataType;
	private ConsoleService console;
	private Program currentProgram;

	public final static String TAG = "Structure Use";

	public RetrieveUsesTask(StructureRecoveryPlugin plugin) {
		super("Retrieve Structure Uses", true, false, false);
		this.plugin = plugin;
		this.targetDataType = plugin.getTargetDataType();
		this.console = plugin.getConsole();
		this.currentProgram = plugin.getCurrentProgram();
	}

	@Override
	public void run(TaskMonitor monitor) {
		String taskName = getTaskTitle();
		Thread.currentThread().setName(taskName);
		try {
			console.addMessage(taskName, "Running...");
			retrieveReferences(monitor);
			console.addMessage(taskName, "Finished!");
		}
		catch (CancelledException e) {
			console.addMessage(taskName, "Cancelled by user.");
		}
		catch (Exception e) {
			if (!monitor.isCancelled()) {
				Msg.showError(this, null, getTaskTitle(), "Error running task: " + taskName +
					"\n" + e.getClass().getName() + ": " + e.getMessage(), e);
				console.addErrorMessage("", "Error running task: " + taskName);
				console.addException(taskName, e);
			}
		}
	}

	protected void retrieveReferences(TaskMonitor monitor) throws CancelledException {
		FieldMatcher fieldMatcher = new FieldMatcher(targetDataType);

		SetAccumulator<LocationReference> accumulator = new SetAccumulator<>();
		ReferenceUtils.findDataTypeFieldReferences(accumulator, fieldMatcher, currentProgram, true,
			monitor);

		Set<Function> toMatch = new HashSet<>();
		Map<String, Set<Function>> byField = new HashMap<>();
		Map<String, AddressSet> toAddressSet = new HashMap<>();

		boolean useBookmarks = plugin.getOptionStructUseBookmarks();
		currentProgram.withTransaction("Add Structure Use Bookmarks", () -> {
			BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
			FunctionManager functionManager = currentProgram.getFunctionManager();
			String typeName = targetDataType.getName();

			for (LocationReference lr : accumulator.get()) {
				String fieldName = lr.getFieldName();
				if (fieldName == null) {
					continue;
				}
				Address locationOfUse = lr.getLocationOfUse();
				Function f = functionManager.getFunctionContaining(locationOfUse);
				if (f == null) {
					continue;
				}
				toAddressSet.computeIfAbsent(fieldName, _ -> new AddressSet())
						.add(locationOfUse);
				byField.computeIfAbsent(fieldName, _ -> new HashSet<Function>()).add(f);
				toMatch.add(f);
				if (useBookmarks) {
					bookmarkManager.setBookmark(locationOfUse, TAG,
						"USES_" + typeName, fieldName);
				}
			}
		});

		plugin.setFunctionsToMatch(toMatch);
		plugin.setFunctionsByField(byField);
		plugin.setAddressesByField(toAddressSet);
	}
}
