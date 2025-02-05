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
package sarif.managers;

import java.io.IOException;
import java.util.*;

import com.google.gson.JsonArray;

import generic.stl.Pair;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.trees.SarifTreeWriter;

/**
 * SARIF manager for program trees.
 */
public class ProgramTreeSarifMgr extends SarifMgr {

	public static String KEY = "PROGRAM_TREES";
	public static String SUBKEY = "ProgramTree";

	private String treeName;
	private TaskMonitor monitor;

	/**
	 * Constructor
	 * 
	 * @param program program
	 * @param log     message log
	 */
	ProgramTreeSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////
	
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor m)
			throws CancelledException {
		this.monitor = m;

		processTree(result);
		return true;
	}

	@SuppressWarnings("unchecked")
	private void processTree(Map<String, Object> result) throws CancelledException {
		treeName = (String) result.get("name");

		ProgramModule root = listing.getRootModule(treeName);
		try {
			try {
				if (root == null) {
					root = listing.createRootModule(treeName);
				}
				String name = root.getName();
				if (name.endsWith(".sarif")) {
					name = name.substring(0, name.indexOf(".sarif"));
				}
				if (name.endsWith(".json")) {
					name = name.substring(0, name.indexOf(".json"));
				}
				root.setName(name);
			} catch (DuplicateNameException dne) {
				// if name already existed, then attempt to create a
				// unique "one-up" name
				//
				int oneUp = 1;
				while (true) {
					try {
						root = listing.createRootModule(treeName + "(" + oneUp + ")");
						break; // we located a unique name...
					} catch (DuplicateNameException e) {
						++oneUp;
					}
				}
				treeName = root.getTreeName();
			}

			Set<AddressRange> ranges = new HashSet<>();
			List<Map<String, Object>> fragments =
				(List<Map<String, Object>>) result.get("fragments");
			for (Map<String, Object> f : fragments) {
				try {
					collectFragmentRanges(ranges, f);
				}
				catch (Exception e) {
					log.appendMsg(e.getMessage());
				}
			}
				
			ProgramFragment depot = root.createFragment("depot");
			for (AddressRange r : ranges) {
				depot.move(r.getMinAddress(), r.getMaxAddress());
			}
			removeEmptyFragments(root);

			List<Map<String, Object>> modules = (List<Map<String, Object>>) result.get("modules");
			for (Map<String, Object> m : modules) {
				monitor.checkCancelled();
				processModule(root, m);
			}
			for (Map<String, Object> f : fragments) {
				monitor.checkCancelled();
				processFragment(root, f);
			}
			root.removeChild("depot");
		}
		catch (NotFoundException | DuplicateNameException | NotEmptyException e) {
			log.appendException(e);
		}
	}

	@SuppressWarnings("unchecked")
	private void processModule(ProgramModule parent, Map<String, Object> module) {
		String name = (String) module.get("name");
		ProgramModule newModule = null;
		try {
			try {
				newModule = parent.createModule(name);
			} catch (DuplicateNameException dne) {
				newModule = listing.getModule(parent.getTreeName(), name);
				if (newModule == null) {
					Msg.error(this, "Duplicate name for " + name);
					return;
				}
				parent.add(newModule);
			}
		} catch (Exception e) {
			log.appendException(e);
		}
		List<Map<String, Object>> modules = (List<Map<String, Object>>) module.get("modules");
		for (Map<String, Object> m : modules) {
			processModule(newModule, m);
		}
		List<Map<String, Object>> fragments = (List<Map<String, Object>>) module.get("fragments");
		for (Map<String, Object> f : fragments) {
			processFragment(newModule, f);
		}
		removeEmptyFragments(newModule);
	}

	private void processFragment(ProgramModule parent, Map<String, Object> fragment) {
		String name = (String) fragment.get("name");
		ProgramFragment frag = null;
		try {
			frag = parent.createFragment(name);
		} catch (DuplicateNameException dne) {
			frag = listing.getFragment(parent.getTreeName(), name);
			try {
				parent.add(frag);
			} catch (DuplicateGroupException dge) {
				// ignore, we are trying to add a fragment to
				// a module that already contains it
			}
		}
		try {
			processFragmentRange(fragment, frag);
		} catch (NotFoundException e) {
			log.appendMsg(e.getMessage());
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	@SuppressWarnings("unchecked")
	private void processFragmentRange(Map<String, Object> fragment, ProgramFragment frag)
			throws AddressFormatException, NotFoundException {

		List<Map<String, Object>> ranges = (List<Map<String, Object>>) fragment.get("ranges");
		for (Map<String, Object> r : ranges) {
			if (monitor.isCancelled()) {
				break;
			}
			String startStr = (String) r.get("start");
			String endStr = (String) r.get("end");

			Address start = parseAddress(factory, startStr);
			Address end = parseAddress(factory, endStr);

			if (start == null || end == null) {
				throw new AddressFormatException(
						"Incompatible Fragment Address Range: [" + startStr + "," + endStr + "]");
			}

			frag.move(start, end);
		}
	}

	@SuppressWarnings("unchecked")
	private void collectFragmentRanges(Set<AddressRange> set, Map<String, Object> fragment)
			throws AddressFormatException {
		List<Map<String, Object>> ranges = (List<Map<String, Object>>) fragment.get("ranges");
		for (Map<String, Object> r : ranges) {
			if (monitor.isCancelled()) {
				break;
			}
			String startStr = (String) r.get("start");
			String endStr = (String) r.get("end");

			Address start = parseAddress(factory, startStr);
			Address end = parseAddress(factory, endStr);

			if (start == null || end == null) {
				throw new AddressFormatException(
					"Incompatible Fragment Address Range: [" + startStr + "," + endStr + "]");
			}

			set.add(new AddressRangeImpl(start, end));
		}
	}

	/**
	 * Method removeEmptyFragments.
	 */
	private void removeEmptyFragments(ProgramModule module) {
		Group[] groups = module.getChildren();
		for (Group group : groups) {
			if (group instanceof ProgramFragment frag) {
				String name = group.getName();
				if (frag.isEmpty()) {
					try {
						module.removeChild(name);
					} catch (NotEmptyException e) {
						log.appendMsg("Warning: Extra Program Tree fragment '" + name
								+ "' did not exist in imported SARIF file");
					}
				}
			} else {
				removeEmptyFragments((ProgramModule) group);
			}
		}
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	/**
	 * Write out the SARIF for the program trees.
	 * 
	 * @param results writer for SARIF
	 * @param addrs   the addresses
	 * @param m       monitor that can be canceled should be written
	 * @throws CancelledException if cancelled
	 */
	void write(JsonArray results, AddressSetView addrs, TaskMonitor m) throws IOException, CancelledException {
		this.monitor = m;
		m.setMessage("Writing PROGRAM TREES ...");

		List<Pair<String, ProgramModule>> request = new ArrayList<>();
		String[] treeNames = listing.getTreeNames();

		for (String n : treeNames) {
			if (m.isCancelled()) {
				throw new CancelledException();
			}
			ProgramModule root = listing.getRootModule(n);
			request.add(new Pair<String, ProgramModule>(n, root));
		}

		writeAsSARIF(request, results);
	}

	public static void writeAsSARIF(List<Pair<String, ProgramModule>> request, JsonArray results) throws IOException {
		SarifTreeWriter writer = new SarifTreeWriter(request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
