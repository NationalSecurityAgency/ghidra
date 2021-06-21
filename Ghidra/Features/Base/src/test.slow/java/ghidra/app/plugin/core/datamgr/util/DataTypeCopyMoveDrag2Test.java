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
package ghidra.app.plugin.core.datamgr.util;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.TestDoubleCategory;
import ghidra.program.model.data.DataType;

public class DataTypeCopyMoveDrag2Test extends AbstractGTest {

	@Test
	public void testGetBaseName() {

		DataTypeTreeCopyMoveTask task = new DataTypeTreeCopyMoveTask();
		String name = "BaseName";
		assertEquals(name, task.getBaseName(name));

		String copyName = "Copy_of_" + name;
		assertEquals(name, task.getBaseName(copyName));

		copyName = "Copy_2_of_" + name;
		assertEquals(name, task.getBaseName(copyName));
	}

	@Test
	public void testGetNextCopyName() {

		DataTypeTreeCopyMoveTask task = new DataTypeTreeCopyMoveTask();
		String name = "BaseName";
		CountBasedStubCategory category = new CountBasedStubCategory("Category", 0);
		assertEquals("Copy_1_of_" + name, task.getNextCopyName(category, name));

		category = new CountBasedStubCategory("Category", 1);
		assertEquals("Copy_2_of_" + name, task.getNextCopyName(category, name));

		category = new CountBasedStubCategory("Category", 10);
		assertEquals("Copy_11_of_" + name, task.getNextCopyName(category, name));
	}

	private class CountBasedStubCategory extends TestDoubleCategory {

		private int threshold;
		private int count;
		private DataType existingType = DataType.DEFAULT;

		CountBasedStubCategory(String name, int threshold) {
			super(name);
			this.threshold = threshold;
		}

		@Override
		public DataType getDataType(String name) {
			if (count++ >= threshold) {
				return null;
			}
			return existingType;
		}
	}
}
