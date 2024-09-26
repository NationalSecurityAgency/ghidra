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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import org.junit.Assert;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import generic.theme.GIcon;
import resources.MultiIcon;
import resources.ResourceManager;

public class FSBIconsTest extends AbstractDockingTest {

	FSBIcons fis = FSBIcons.getInstance();

	@Test
	public void testGetIcon() {
		Icon icon = fis.getIcon("blah.txt", null);
		Assert.assertNotNull(icon);
		assertTrue(icon instanceof GIcon);
		GIcon gIcon = (GIcon) icon;
		assertEquals("icon.fsbrowser.file.extension.txt", gIcon.getId());
	}

	@Test
	public void testGetOverlayIcon() {
		Icon icon = fis.getIcon("blah.txt", List.of(FSBIcons.FILESYSTEM_OVERLAY_ICON));
		Assert.assertNotNull(icon);
		assertTrue(icon instanceof MultiIcon);
		MultiIcon multiIcon = (MultiIcon) icon;
		assertEquals(
			"MultiIcon[icon.fsbrowser.file.extension.txt, icon.fsbrowser.file.overlay.filesystem]",
			multiIcon.toString());
	}

	@Test
	public void testGetSubstringIcon() {
		Icon icon = fis.getIcon("blah.release.abcx.123", null);
		Assert.assertNotNull(icon);
		assertTrue(icon instanceof GIcon);
		GIcon gIcon = (GIcon) icon;
		assertEquals("icon.fsbrowser.file.substring.release.", gIcon.getId());
	}

	@Test
	public void testNoMatch() {
		Icon icon = fis.getIcon("aaaaaaaa.bbbbbbbb.cccccccc", null);
		assertEquals(FSBIcons.DEFAULT_ICON, icon);
	}

	@Test
	public void testImageManagerLoadedIconResources()
			throws IllegalArgumentException, IllegalAccessException {

		ImageIcon defaultIcon = ResourceManager.getDefaultIcon();

		Set<String> failedIcons = new HashSet<>();
		for (Field field : FSBIcons.class.getDeclaredFields()) {
			if (Modifier.isStatic(field.getModifiers()) &&
				field.getType().equals(ImageIcon.class)) {
				Object fieldValue = field.get(null);
				if (fieldValue == null || fieldValue == defaultIcon) {
					failedIcons.add(field.getName());
				}
			}
		}
		Assert.assertTrue("Some icons failed to load or misconfigured: " + failedIcons.toString(),
			failedIcons.isEmpty());
	}
}
