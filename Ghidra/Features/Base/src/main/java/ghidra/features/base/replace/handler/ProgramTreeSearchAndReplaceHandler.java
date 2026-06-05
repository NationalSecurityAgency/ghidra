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
package ghidra.features.base.replace.handler;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.replace.*;
import ghidra.features.base.replace.items.RenameProgramTreeGroupQuickFix;
import ghidra.program.model.listing.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link SearchAndReplaceHandler} for handling search and replace for program tree modules and
 * fragments.
 */

public class ProgramTreeSearchAndReplaceHandler extends SearchAndReplaceHandler {

	public ProgramTreeSearchAndReplaceHandler() {
		addType(new SearchType(this, "Program Trees",
			"Search and replace program tree module and fragment names"));
	}

	@Override
	public void findAll(Program program, SearchAndReplaceQuery query,
			Accumulator<QuickFix> accumulator, TaskMonitor monitor) throws CancelledException {

		Listing listing = program.getListing();
		String[] treeNames = listing.getTreeNames();
		monitor.initialize(treeNames.length, "Search Program Trees");
		for (String treeName : treeNames) {
			monitor.increment();
			findAll(program, treeName, query, accumulator, monitor);
		}
	}

	private void findAll(Program program, String treeName, SearchAndReplaceQuery query,
			Accumulator<QuickFix> accumulator, TaskMonitor monitor) throws CancelledException {

		Set<Group> set = gatherProgramTreeGroups(program, treeName, monitor);
		Pattern pattern = query.getSearchPattern();

		/**
		 * Check all the modules and fragments in the tree
		 */
		for (Group group : set) {
			String name = group.getName();
			Matcher matcher = pattern.matcher(name);
			if (matcher.find()) {
				String newName = matcher.replaceAll(query.getReplacementText());
				QuickFix item = new RenameProgramTreeGroupQuickFix(program, group, newName);
				accumulator.add(item);
			}
		}

	}

	private Set<Group> gatherProgramTreeGroups(Program program, String treeName,
			TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getRootModule(treeName);

		Set<Group> set = new HashSet<>();
		addProgramTreeGroupsRecursively(set, rootModule, monitor);

		// The root module name is the name of the program. Don't allow to change it here.
		set.remove(rootModule);
		return set;
	}

	private void addProgramTreeGroupsRecursively(Set<Group> set, Group group, TaskMonitor monitor) {
		set.add(group);
		if (group instanceof ProgramModule module) {
			Group[] children = module.getChildren();
			for (Group child : children) {
				addProgramTreeGroupsRecursively(set, child, monitor);
			}
		}
	}
}
