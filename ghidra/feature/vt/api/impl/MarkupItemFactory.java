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
package ghidra.feature.vt.api.impl;

import ghidra.feature.vt.api.db.VTAssociationDB;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.markuptype.VTMarkupTypeFactory;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class MarkupItemFactory {

	private MarkupItemFactory() {
		// no-no
	}

	public static Collection<VTMarkupItem> generateMarkupItems(TaskMonitor monitor,
			VTAssociationDB association) throws CancelledException {
		List<VTMarkupItem> list = new ArrayList<VTMarkupItem>();

		List<VTMarkupType> values = VTMarkupTypeFactory.getMarkupTypes();

		monitor.setMessage("Searching unapplied for markup items");
		monitor.initialize(values.size());

		VTAssociationType associationType = association.getType();
		for (VTMarkupType type : values) {
			monitor.checkCanceled();
			if (type.supportsAssociationType(associationType)) {
				list.addAll(createMarkupItems(type, association));
			}
			monitor.incrementProgress(1);
		}

		monitor.setProgress(values.size());
		return list;
	}

	// let the exception block handle the cast exception
	private static List<VTMarkupItem> createMarkupItems(VTMarkupType type,
			VTAssociationDB association) {

		try {
			return type.createMarkupItems(association);
		}
		catch (Exception e) {
			Msg.debug(MarkupItemFactory.class, "Unexpected exception creating markup items.  ", e);
		}
		return Collections.emptyList();
	}
}
