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

import static org.junit.Assert.*;

import java.util.List;

import javax.swing.Icon;

import org.junit.Assert;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import generic.theme.GIcon;
import resources.MultiIcon;

public class FileIconServiceTest extends AbstractDockingTest {

	@Test
	public void testGetIcon() {
		FileIconService fis = FileIconService.getInstance();
		Icon icon = fis.getIcon("blah.txt", null);
		Assert.assertNotNull(icon);
		assertTrue(icon instanceof GIcon);
		GIcon gIcon = (GIcon) icon;
		assertEquals("icon.fsbrowser.file.extension.txt", gIcon.getId());
	}

	@Test
	public void testGetOverlayIcon() {
		FileIconService fis = FileIconService.getInstance();
		Icon icon = fis.getIcon("blah.txt", List.of(FileIconService.FILESYSTEM_OVERLAY_ICON));
		Assert.assertNotNull(icon);
		assertTrue(icon instanceof MultiIcon);
		MultiIcon multiIcon = (MultiIcon) icon;
		assertEquals(
			"MultiIcon[icon.fsbrowser.file.extension.txt, icon.fsbrowser.file.overlay.filesystem]",
			multiIcon.toString());
	}

	@Test
	public void testGetSubstringIcon() {
		FileIconService fis = FileIconService.getInstance();
		Icon icon = fis.getIcon("blah.release.abcx.123", null);
		Assert.assertNotNull(icon);
		assertTrue(icon instanceof GIcon);
		GIcon gIcon = (GIcon) icon;
		assertEquals("icon.fsbrowser.file.substring.release.", gIcon.getId());
	}

	@Test
	public void testNoMatch() {
		FileIconService fis = FileIconService.getInstance();
		Icon icon = fis.getIcon("aaaaaaaa.bbbbbbbb.cccccccc", null);
		assertEquals(FileIconService.DEFAULT_ICON, icon);
	}
}
