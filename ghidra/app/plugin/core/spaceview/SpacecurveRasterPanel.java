/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.spaceview;

import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.image.*;
import java.util.Hashtable;

import javax.swing.JFrame;
import javax.swing.JPanel;

public class SpacecurveRasterPanel extends JPanel {
	protected static final Hashtable<?, ?> EMPTY_HASHTABLE = new Hashtable<Object, Object>();

	byte[] raster;
	private int width;
	private int height;
	private IndexColorModel colorModel;

	public SpacecurveRasterPanel(IndexColorModel colorModel) {
		this.colorModel = colorModel;
	}

	public void setRaster(byte[] raster, int width, int height) {
		if (raster.length != width * height) {
			throw new IllegalArgumentException("raster.length != width * height");
		}
		this.raster = raster;
		this.width = width;
		this.height = height;
		repaint();
	}

	public void setColorModel(IndexColorModel colorModel) {
		this.colorModel = colorModel;
		repaint();
	}

	@Override
	public void paintComponent(Graphics g) {
		super.paintComponent(g);
		Graphics2D g2 = (Graphics2D) g;

		if (raster != null) {
			DataBufferByte dbb = new DataBufferByte(raster, height * width, 0);
			ComponentSampleModel sm = getComponentSampleModel();
			WritableRaster wr = Raster.createWritableRaster(sm, dbb, null);
			BufferedImage img = new BufferedImage(colorModel, wr, true, EMPTY_HASHTABLE);

			g2.drawImage(img, 0, 0, null);
		}
	}

	protected ComponentSampleModel getComponentSampleModel() {
		return new ComponentSampleModel(DataBuffer.TYPE_BYTE, width, height, 1, width,
			new int[] { 0 });
	}

	public static void main(String[] args) {
		byte[] red = new byte[256];
		byte[] grn = new byte[256];
		byte[] blu = new byte[256];
		for (int ii = 0; ii < 256; ++ii) {
			int jj = (255 - ii);
			red[ii] = (byte) jj;
			grn[ii] = (byte) (jj * jj / 255);
			blu[ii] = (byte) (Math.sqrt(jj) / Math.sqrt(255.0) * 255.0);
		}
		IndexColorModel colorModel = new IndexColorModel(8, 256, red, grn, blu);
		final int width = 256;
		final int height = 256;
		byte[] raster = new byte[width * height];
		for (int ii = 0; ii < raster.length; ++ii) {
			raster[ii] = (byte) ((ii * 1) % 256);
		}
		SpacecurveRasterPanel panel = new SpacecurveRasterPanel(colorModel);
		panel.setRaster(raster, width, height);
		JFrame frame = new JFrame();
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().add(panel);
		frame.setSize(width, height);
		frame.setVisible(true);
	}
}
