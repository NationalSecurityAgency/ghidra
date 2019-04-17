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
package ghidra.app.plugin.core.interpreter;

import java.util.ArrayList;

class HistoryManagerImpl implements HistoryManager {
	private ArrayList<String> history = new ArrayList<String>();
	private int position = 0;

	@Override
	public void addHistory(String command) {
		// ignore empty lines
		if (command.matches("^\\s*$")) {
			return;
		}
		// should be ALL the time
		if (command.charAt(command.length() - 1) == '\n') {
			command = command.substring(0, command.length() - 1);
		}
		history.add(command);
		position = history.size();
	}

	@Override
	public String getHistoryUp() {
		if (position > 0) {
			--position;
			return history.get(position);
		}
		return null;
	}

	@Override
	public String getHistoryDown() {
		if (position < history.size() - 1) {
			++position;
			String result = history.get(position);
			return result;
		}
		if (position == history.size() - 1) {
			position = history.size();
			return "";
		}
		return null;
	}

	@Override
	public void setRetention(int retention) {
		// ignore for now
	}

	@Override
	public int getRetention() {
		return Integer.MAX_VALUE;
	}
}
