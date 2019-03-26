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
package ghidra.plugins.fsbrowser;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class FileIconServiceTest extends AbstractGenericTest
{

	@Test
	public void testGetIcon() {
		FileIconService fis = FileIconService.getInstance();
		Assert.assertNotNull(fis.getImage("blah.txt"));
	}

	@Test
	public void testGetOverlayIcon() {
		FileIconService fis = FileIconService.getInstance();
		Assert.assertNotNull(fis.getImage("blah.txt", FileIconService.OVERLAY_FILESYSTEM));
	}
}
