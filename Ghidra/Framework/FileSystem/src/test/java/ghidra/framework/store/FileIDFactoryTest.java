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
package ghidra.framework.store;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.HashSet;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class FileIDFactoryTest extends AbstractGenericTest {

	public FileIDFactoryTest() {
		super();
	}
	
@Test
    public void testCreateFileID() {
		long start = (new Date()).getTime();
		HashSet<String> idSet = new HashSet<String>();
		int count = 100;
		for (int i = 0; i < count; i++) {
			idSet.add(FileIDFactory.createFileID());
		}
		assertEquals(count, idSet.size());
		long end = (new Date()).getTime();
		long t = (end - start) / count;
		System.out.println("FileIDFactoryTest.createFileID average time: " + t + " ms");
	}

}
