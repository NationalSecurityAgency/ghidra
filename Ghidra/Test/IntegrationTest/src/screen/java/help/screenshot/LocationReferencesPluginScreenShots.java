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
package help.screenshot;

import java.awt.Rectangle;

import org.junit.Test;

import docking.ComponentProvider;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.app.util.viewer.field.XRefFieldFactory;

public class LocationReferencesPluginScreenShots extends GhidraScreenShotGenerator {

	public LocationReferencesPluginScreenShots() {
		super();
	}

@Test
    public void testReferencesToDialog() {

		goToListing(0x4075db);

		performAction("Find References To", "LocationReferencesPlugin", true);

		ComponentProvider provider = getProvider("Location References Provider");
		captureIsolatedProviderWindow(provider.getClass(), 600, 350);
	}

@Test
    public void testLabelReferencesSample() {

		positionListingCenter(0x407685);
		positionCursor(0x407685, OperandFieldFactory.FIELD_NAME);

		captureToolWindow(1000, 1000);
		crop(new Rectangle(300, 338, 400, 28));
	}

@Test
    public void testXRefLabelReferencesSample() {

		positionListingCenter(0x40768a);
		positionCursor(0x4078d7, XRefFieldFactory.FIELD_NAME);

		captureToolWindow(1200, 1000);
		crop(new Rectangle(480, 300, 590, 90));
	}
}
