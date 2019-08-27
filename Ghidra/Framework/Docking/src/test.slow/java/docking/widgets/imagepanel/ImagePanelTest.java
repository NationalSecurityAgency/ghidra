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
package docking.widgets.imagepanel;

import static org.junit.Assert.assertTrue;

import java.awt.Image;

import javax.swing.Icon;
import javax.swing.JFrame;

import org.junit.*;

import docking.test.AbstractDockingTest;
import resources.ResourceManager;
import resources.icons.EmptyIcon;

public class ImagePanelTest extends AbstractDockingTest {

	private JFrame frame;
	private ImagePanel imagePanel;

	@Before
	public void setUp() throws Exception {
		Icon emptyIcon = new EmptyIcon(32, 32);
		Image emptyImage = ResourceManager.getImageIcon(emptyIcon).getImage();
		imagePanel = new ImagePanel(emptyImage);

		frame = new JFrame("ImagePanel Test");
		frame.getContentPane().add(imagePanel);
		frame.setSize(400, 400);

		frame.setVisible(true);
	}

	@After
	public void tearDown() throws Exception {
		frame.dispose();
	}

	private void reset() {
		imagePanel.setZoomFactor(1.0f);

		assertTrue("Unable to reset zoom factor",
			Float.compare(imagePanel.getZoomFactor(), 1.0f) == 0);

	}

	@Test
	public void testZoom_Neutral() {
		reset();

		imagePanel.setZoomFactor(1.0f);

		assertTrue("Zoom factor not set to 1.0x",
			Float.compare(imagePanel.getZoomFactor(), 1.0f) == 0);
	}

	@Test
	public void testZoom_10Point0f() {
		reset();

		imagePanel.setZoomFactor(10.0f);

		assertTrue("Zoom factor not set to 10.0x",
			Float.compare(imagePanel.getZoomFactor(), 10.0f) == 0);
	}

	@Test
	public void testZoom_0Point05() {
		reset();

		imagePanel.setZoomFactor(0.05f);

		assertTrue("Zoom factor not set to 0.05x",
			Float.compare(imagePanel.getZoomFactor(), 0.05f) == 0);
	}

	@Test
	public void testZoom_20Point0() {
		reset();

		imagePanel.setZoomFactor(20.0f);

		assertTrue("Zoom factor not set to 20.0x; should be 10.0x",
			Float.compare(imagePanel.getZoomFactor(), 10.0f) == 0);
	}

	@Test
	public void testZoom_0Point001() {
		reset();

		imagePanel.setZoomFactor(0.001f);

		assertTrue("Zoom factor not set to 0.001x; should be 0.05x",
			Float.compare(imagePanel.getZoomFactor(), 0.05f) == 0);
	}

	@Test
	public void testZoom_3Point75() {
		reset();

		imagePanel.setZoomFactor(3.75f);

		assertTrue("Zoom factor not set to 3.75x; should be 4.0x",
			Float.compare(imagePanel.getZoomFactor(), 4.0f) == 0);
	}

}
