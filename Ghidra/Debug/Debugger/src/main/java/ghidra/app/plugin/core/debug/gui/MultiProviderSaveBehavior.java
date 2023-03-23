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

import java.util.List;
import java.util.function.BiConsumer;

import org.jdom.Element;

import ghidra.app.plugin.core.debug.gui.MultiProviderSaveBehavior.SaveableProvider;
import ghidra.framework.options.SaveState;

public abstract class MultiProviderSaveBehavior<P extends SaveableProvider> {
	private static final String KEY_CONNECTED_PROVIDER = "connectedProvider";
	private static final String KEY_DISCONNECTED_COUNT = "disconnectedCount";
	private static final String PREFIX_DISCONNECTED_PROVIDER = "disconnectedProvider";

	public interface SaveableProvider {
		void writeConfigState(SaveState saveState);

		void readConfigState(SaveState saveState);

		void writeDataState(SaveState saveState);

		void readDataState(SaveState saveState);
	}

	protected abstract P getConnectedProvider();

	protected abstract List<P> getDisconnectedProviders();

	protected abstract P createDisconnectedProvider();

	protected abstract void removeDisconnectedProvider(P p);

	protected void doWrite(SaveState saveState, BiConsumer<? super P, ? super SaveState> writer) {
		P cp = getConnectedProvider();
		SaveState cpState = new SaveState();
		writer.accept(cp, cpState);
		saveState.putXmlElement(KEY_CONNECTED_PROVIDER, cpState.saveToXml());

		List<P> disconnectedProviders = getDisconnectedProviders();
		List<P> disconnected;
		synchronized (disconnectedProviders) {
			disconnected = List.copyOf(disconnectedProviders);
		}
		saveState.putInt(KEY_DISCONNECTED_COUNT, disconnected.size());
		for (int i = 0; i < disconnected.size(); i++) {
			P dp = disconnected.get(i);
			String stateName = PREFIX_DISCONNECTED_PROVIDER + i;
			SaveState dpState = new SaveState();
			writer.accept(dp, dpState);
			saveState.putXmlElement(stateName, dpState.saveToXml());
		}
	}

	protected void doRead(SaveState saveState, BiConsumer<? super P, ? super SaveState> reader,
			boolean matchCount) {
		Element cpElement = saveState.getXmlElement(KEY_CONNECTED_PROVIDER);
		if (cpElement != null) {
			P cp = getConnectedProvider();
			SaveState cpState = new SaveState(cpElement);
			reader.accept(cp, cpState);
		}

		int disconnectedCount = saveState.getInt(KEY_DISCONNECTED_COUNT, 0);
		List<P> disconnectedProviders = getDisconnectedProviders();
		while (matchCount && disconnectedProviders.size() < disconnectedCount) {
			createDisconnectedProvider();
		}
		while (matchCount && disconnectedProviders.size() > disconnectedCount) {
			removeDisconnectedProvider(disconnectedProviders.get(disconnectedProviders.size() - 1));
		}

		int count = Math.min(disconnectedCount, disconnectedProviders.size());
		for (int i = 0; i < count; i++) {
			String stateName = PREFIX_DISCONNECTED_PROVIDER + i;
			Element dpElement = saveState.getXmlElement(stateName);
			if (dpElement != null) {
				P dp = disconnectedProviders.get(i);
				SaveState dpState = new SaveState(dpElement);
				reader.accept(dp, dpState);
			}
		}
	}

	public void writeConfigState(SaveState saveState) {
		doWrite(saveState, P::writeConfigState);
	}

	public void readConfigState(SaveState saveState) {
		doRead(saveState, P::readConfigState, true);
	}

	public void writeDataState(SaveState saveState) {
		doWrite(saveState, P::writeDataState);
	}

	public void readDataState(SaveState saveState) {
		doRead(saveState, P::readDataState, false);
	}
}
