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
package ghidra.app.plugin.core.gotoquery;

import ghidra.app.nav.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import java.util.*;

import org.jdom.Element;

import docking.ComponentProvider;

public class DefaultNavigatableLocationMemento extends LocationMemento {
	private final Map<Navigatable, LocationMemento> mementos =
		new HashMap<Navigatable, LocationMemento>();
	private Navigatable focusedNavigatable;

	public DefaultNavigatableLocationMemento(Program program, ProgramLocation location,
			PluginTool tool) {
		super(program, location);

		ComponentProvider activeProvider = tool.getActiveComponentProvider();

		List<Navigatable> navigatables = NavigatableRegistry.getRegisteredNavigatables(tool);
		for (Navigatable navigatable : navigatables) {
			if (!(navigatable instanceof GoToServicePlugin.DefaultNavigatable) &&
				navigatable.isConnected() && navigatable.isVisible()) {
				if (navigatable == activeProvider) {
					focusedNavigatable = navigatable;
				}
				LocationMemento memento = navigatable.getMemento();
				if (memento.isValid()) {
					mementos.put(navigatable, memento);
				}
			}
		}
	}

	public DefaultNavigatableLocationMemento(SaveState saveState, Program[] programs) {
		super(saveState, programs);
		long navID = saveState.getLong("FOCUSED_NAV", 0);
		focusedNavigatable = NavigatableRegistry.getNavigatable(navID);
		int count = saveState.getInt("NUM_MEMENTOS", 0);

		for (int i = 0; i < count; i++) {
			Element element = saveState.getXmlElement("MEMENTO" + i);
			if (element != null) {
				SaveState navState = new SaveState(element);
				navID = navState.getLong("NAV_ID", 0);
				Navigatable nav = NavigatableRegistry.getNavigatable(navID);
				LocationMemento memento = LocationMemento.getLocationMemento(navState, programs);
				if (nav != null && memento != null) {
					mementos.put(nav, memento);
				}
			}
		}
	}

	public Navigatable getFocusedNavigatable() {
		return focusedNavigatable;
	}

	public void setMementos() {
		for (Navigatable navigatable : mementos.keySet()) {
			if (!navigatable.isVisible()) {
				continue;
			}
			LocationMemento memento = mementos.get(navigatable);
			navigatable.setMemento(memento);
		}
	}

	@Override
	public void saveState(SaveState saveState) {
		super.saveState(saveState);
		saveState.putInt("NUM_MEMENTOS", mementos.size());
		if (focusedNavigatable != null) {
			saveState.putLong("FOCUSED_NAV", focusedNavigatable.getInstanceID());
		}
		int index = 0;
		for (Navigatable navigatable : mementos.keySet()) {
			LocationMemento memento = mementos.get(navigatable);
			SaveState mementoSaveState = new SaveState();
			mementoSaveState.putLong("NAV_ID", navigatable.getInstanceID());
			memento.saveState(mementoSaveState);
			Element element = mementoSaveState.saveToXml();
			saveState.putXmlElement("MEMENTO" + index, element);
			index++;
		}
	}
}
