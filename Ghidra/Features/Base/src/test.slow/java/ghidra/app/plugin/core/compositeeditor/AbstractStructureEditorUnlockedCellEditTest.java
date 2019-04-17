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
package ghidra.app.plugin.core.compositeeditor;

import org.junit.Assert;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public abstract class AbstractStructureEditorUnlockedCellEditTest
		extends AbstractStructureEditorTest {

	protected void init(final Structure dt, final Category cat) {
		final DataType dtClone = dt.clone(programDTM);
		try {
			dtClone.setCategoryPath(cat.getCategoryPath());
		}
		catch (DuplicateNameException e) {
			Assert.fail(e.getMessage());
		}
		runSwing(() -> {
			installProvider(new StructureEditorProvider(plugin, (Structure) dtClone, false));
			model = provider.getModel();
		});
		waitForSwing();

		getActions();
	}
}
