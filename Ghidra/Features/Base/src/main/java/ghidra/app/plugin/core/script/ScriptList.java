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
package ghidra.app.plugin.core.script;

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.*;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.util.Swing;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.task.SwingUpdateManager;

/**
 * Loads and manages updating of available script files.   
 * <p>
 * Use the {@link #refresh()} method to reload the script files.
 */
public class ScriptList {

	private BundleHost bundleHost;
	private List<ResourceFile> scriptFiles = new ArrayList<>();
	private WeakSet<ChangeListener> listeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private SwingUpdateManager refreshUpdateManager = new SwingUpdateManager(this::doRefresh);

	ScriptList(BundleHost bundleHost) {
		this.bundleHost = bundleHost;
	}

	void addListener(ChangeListener l) {
		listeners.add(l);
	}

	void removeListener(ChangeListener l) {
		listeners.remove(l);
	}

	private void notifyScriptsChanged() {
		ChangeEvent e = new ChangeEvent(this);
		listeners.forEach(l -> l.stateChanged(e));
	}

	void refresh() {
		refreshUpdateManager.update();
	}

	private void doRefresh() {
		List<ResourceFile> scriptAccumulator = new ArrayList<>();
		for (ResourceFile bundleDir : getScriptDirectories()) {
			updateAvailableScriptFilesForDirectory(scriptAccumulator, bundleDir);
		}

		scriptFiles = scriptAccumulator;

		notifyScriptsChanged();
	}

	void load() {
		Swing.runNow(() -> {
			if (scriptFiles.isEmpty()) {
				doRefresh();
			}
		});
	}

	List<ResourceFile> getScriptFiles() {
		load(); // ensure the scripts have been loaded
		return Collections.unmodifiableList(scriptFiles);
	}

	List<ResourceFile> getScriptDirectories() {
		return bundleHost.getGhidraBundles()
				.stream()
				.filter(GhidraSourceBundle.class::isInstance)
				.filter(GhidraBundle::isEnabled)
				.map(GhidraBundle::getFile)
				.collect(Collectors.toList());
	}

	private void updateAvailableScriptFilesForDirectory(
			List<ResourceFile> scriptAccumulator, ResourceFile directory) {
		ResourceFile[] files = directory.listFiles();
		if (files == null) {
			return;
		}

		for (ResourceFile scriptFile : files) {
			if (scriptFile.isFile() && GhidraScriptUtil.hasScriptProvider(scriptFile)) {
				scriptAccumulator.add(scriptFile);
			}
		}

	}
}
