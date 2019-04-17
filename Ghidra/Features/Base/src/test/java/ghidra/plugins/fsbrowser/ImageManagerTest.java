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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;

import javax.swing.ImageIcon;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import resources.ResourceManager;

public class ImageManagerTest extends AbstractGenericTest {


	@Test
	public void testImageManagerLoadedIconResources()
			throws IllegalArgumentException, IllegalAccessException {

		ImageIcon defaultIcon = ResourceManager.getDefaultIcon();

		Set<String> failedIcons = new HashSet<>();
		for (Field field : ImageManager.class.getDeclaredFields()) {
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
