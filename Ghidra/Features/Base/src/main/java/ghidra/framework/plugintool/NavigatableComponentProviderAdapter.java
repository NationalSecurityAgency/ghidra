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
package ghidra.framework.plugintool;

import ghidra.app.nav.*;
import ghidra.framework.options.SaveState;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

import javax.swing.Icon;
import javax.swing.ImageIcon;

public abstract class NavigatableComponentProviderAdapter extends ComponentProviderAdapter
		implements Navigatable {

	private WeakSet<NavigatableRemovalListener> navigationListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private boolean isConnected;

	private ImageIcon navigatableIcon;

	private boolean disposed = false;

	public NavigatableComponentProviderAdapter(PluginTool tool, String name, String owner,
			Class<?> contextType) {
		super(tool, name, owner, contextType);
		registerNavigatable();
	}

	@Override
	public Icon getIcon() {
		if (isConnected()) {
			return super.getIcon();
		}

		if (navigatableIcon == null) {
			Icon primaryIcon = super.getIcon();
			navigatableIcon = NavigatableIconFactory.createSnapshotOverlayIcon(primaryIcon);
		}
		return navigatableIcon;
	}

	@Override
	public Icon getNavigatableIcon() {
		return getIcon();
	}

	@Override
	public boolean isConnected() {
		return isConnected;
	}

	@Override
	public boolean supportsMarkers() {
		return isConnected;
	}

	protected void setConnected(boolean newValue) {
		isConnected = newValue;
	}

	@Override
	public boolean isDisposed() {
		return disposed;
	}

	public void dispose() {
		unregisterNavigatable();
		disposed = true;
		for (NavigatableRemovalListener listener : navigationListeners) {
			listener.navigatableRemoved(this);
		}
	}

	void registerNavigatable() {
		NavigatableRegistry.registerNavigatable(tool, this);
	}

	void unregisterNavigatable() {
		NavigatableRegistry.unregisterNavigatable(tool, this);
	}

	@Override
	public void addNavigatableListener(NavigatableRemovalListener listener) {
		navigationListeners.add(listener);
	}

	@Override
	public void removeNavigatableListener(NavigatableRemovalListener listener) {
		navigationListeners.remove(listener);
	}

	public void readDataState(SaveState saveState) {
		unregisterNavigatable();
		initializeInstanceID(saveState.getLong("NAV_ID", getInstanceID()));
		registerNavigatable();
	}

	public void writeDataState(SaveState saveState) {
		saveState.putLong("NAV_ID", getInstanceID());
	}

}
