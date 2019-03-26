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
package ghidra.feature.vt.gui.task;

import ghidra.feature.vt.api.util.VersionTrackingApplyException;

import java.util.ArrayList;
import java.util.List;

public class ErrorStatus {
	private List<Exception> exceptions = new ArrayList<Exception>();

	boolean hasErrors() {
		return exceptions.size() > 0;
	}

	public String printMessage() {
		StringBuilder buildy = new StringBuilder("<html>");
		for (Exception exception : exceptions) {
			buildy.append(exception.getMessage()).append("<br>");
		}
		return buildy.toString();
	}

	public String printLogMessage() {
		StringBuilder buildy = new StringBuilder();
		for (Exception exception : exceptions) {
			buildy.append(exception.getMessage()).append('\n');
		}
		return buildy.toString();
	}

	public void addException(VersionTrackingApplyException e) {
		exceptions.add(e);
	}

	public List<Exception> getExceptions() {
		return exceptions;
	}
}
