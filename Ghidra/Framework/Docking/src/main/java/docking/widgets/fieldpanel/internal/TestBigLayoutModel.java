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
package docking.widgets.fieldpanel.internal;

import java.awt.*;
import java.math.BigInteger;
import java.util.ArrayList;

import javax.swing.JButton;
import javax.swing.JFrame;

import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;

public class TestBigLayoutModel implements LayoutModel {
	private static final Highlight[] NO_HIGHLIGHTS = new Highlight[0];
	private static final HighlightFactory hlFactory =
		(field, text, cursorTextOffset) -> NO_HIGHLIGHTS;
	ArrayList<LayoutModelListener> listeners = new ArrayList<LayoutModelListener>();

	FontMetrics fm;
	//	BigInteger numIndexes = BigInteger.valueOf(1000000000000000L);
	BigInteger numIndexes = BigInteger.valueOf(55);
	private final String name;
	private int startBigSizes = 0;
	private int endBigSizes = -1;

	/**
	 * 
	 */
	public TestBigLayoutModel(FontMetrics fm, String name, BigInteger numIndexes) {
		this.fm = fm;
		this.name = name;
		this.numIndexes = numIndexes;
	}

	public void setNumIndexes(BigInteger n) {
		this.numIndexes = n;
		for (LayoutModelListener listener : listeners) {
			listener.modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
		}
	}

	@Override
	public boolean isUniform() {
		return false;
	}

	@Override
	public Dimension getPreferredViewSize() {
		return new Dimension(500, 500);
	}

	@Override
	public BigInteger getNumIndexes() {
		return numIndexes;
	}

	@Override
	public Layout getLayout(BigInteger index) {
		if (index.compareTo(BigInteger.ZERO) < 0) {
			return null;
		}
		if (index.compareTo(numIndexes) >= 0) {
			return null;
		}
		String text = name + ": This is line " + index +
			" More text to make line longer abcdefghijklmnopqrstuvwxyzabcdefghijk";
		FieldElement fe1 = new TextFieldElement(new AttributedString(text, Color.BLACK, fm), 0, 0);
		FieldElement fe2 =
			new TextFieldElement(new AttributedString("More text", Color.BLACK, fm), 0, 0);
		SingleRowLayout layout = new SingleRowLayout(new ClippingTextField(20, 300, fe1, hlFactory),
			new ClippingTextField(330, 100, fe2, hlFactory));

		if (index.intValue() >= startBigSizes && index.intValue() <= endBigSizes) {
			layout.insertSpaceAbove(30);
		}
		return layout;
	}

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		listeners.remove(listener);
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		BigInteger nextIndex = index.add(BigInteger.ONE);
		if (nextIndex.compareTo(numIndexes) >= 0) {
			return null;
		}
		return nextIndex;
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if (index.compareTo(BigInteger.ZERO) <= 0) {
			return null;
		}
		if (index.compareTo(numIndexes) >= 0) {
			index = numIndexes;
		}
		return index.subtract(BigInteger.ONE);
	}

	public static void main(String[] args) {
		final Font font = new Font("monospace", Font.PLAIN, 12);
		final JFrame frame = new JFrame();
		final TestBigLayoutModel model =
			new TestBigLayoutModel(frame.getFontMetrics(font), "AAA", BigInteger.valueOf(1000000L));
		final FieldPanel provider = new FieldPanel(model);
		IndexedScrollPane scrollPanel = new IndexedScrollPane(provider);
		Container contentPane = frame.getContentPane();
		contentPane.setLayout(new BorderLayout());
		contentPane.add(scrollPanel);
		JButton button = new JButton("Hit Me");
		button.addActionListener(e -> model.updateData(1000, 2000));
		contentPane.add(button, BorderLayout.SOUTH);
		frame.pack();
		frame.setVisible(true);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.repaint();

	}

	protected void updateData(int i, int j) {
		int notifyStart = Math.min(i, startBigSizes);
		int notifyEnd = Math.max(j, endBigSizes);
		startBigSizes = i;
		endBigSizes = j;
		for (LayoutModelListener listener : listeners) {
			listener.dataChanged(BigInteger.valueOf(notifyStart), BigInteger.valueOf(notifyEnd));
		}

	}

	@Override
	public void flushChanges() {
	}

}
