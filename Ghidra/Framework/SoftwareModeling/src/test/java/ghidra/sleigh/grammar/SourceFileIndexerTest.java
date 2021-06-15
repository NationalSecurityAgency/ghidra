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
package ghidra.sleigh.grammar;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class SourceFileIndexerTest extends AbstractGenericTest {

	@Test
	public void basicTest() {
		Location loc1_1 = new Location("file1", 1);
		Location loc1_2 = new Location("file1", 2);
		Location loc2_1 = new Location("file2", 11);
		Location loc2_2 = new Location("file2", 22);
		Location loc3_1 = new Location("file3", 111);
		Location loc3_2 = new Location("file3", 222);
		Location nullLocation = null;
		Location nullFilename = new Location(null, 1000);

		SourceFileIndexer indexer = new SourceFileIndexer();
		indexer.index(loc1_1);
		indexer.index(loc1_2);
		indexer.index(loc3_2);
		int ret2_1 = indexer.index(loc2_1);
		indexer.index(nullLocation);
		indexer.index(loc3_1);
		indexer.index(nullFilename);
		int ret2_2 = indexer.index(loc2_2);

		assertEquals(ret2_1, ret2_2);

		int file1_index = indexer.getIndex(loc1_1.filename);
		assertEquals(file1_index, indexer.getIndex(loc1_2.filename).intValue());

		int file2_index = indexer.getIndex(loc2_1.filename);
		assertEquals(file2_index, indexer.getIndex(loc2_2.filename).intValue());

		int file3_index = indexer.getIndex(loc3_1.filename);
		assertEquals(file3_index, indexer.getIndex(loc3_2.filename).intValue());

		assertNotEquals(file1_index, file2_index);
		assertNotEquals(file1_index, file3_index);
		assertNotEquals(file2_index, file3_index);
	}

}
