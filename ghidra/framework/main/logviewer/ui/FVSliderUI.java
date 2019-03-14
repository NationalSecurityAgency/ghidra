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
package ghidra.framework.main.logviewer.ui;

import java.io.IOException;
import java.util.Iterator;

import javax.swing.*;
import javax.swing.plaf.basic.BasicSliderUI;

import ghidra.framework.main.logviewer.model.*;
import ghidra.util.Msg;

/**
 * Custom UI for a slider that dynamically adjusts the thumb height based on the size of the
 * given {@link JScrollPane} and {JTable}.
 * 
 * Note: This is used instead of a {link BasicScrollBarUI} instance because of the complexity
 * of trying to adjust the thumb size of a {@link JScrollBar} that is not attached to a 
 * {@link JScrollPane} instance.
 * 
 */
public class FVSliderUI extends BasicSliderUI {

	private JScrollPane scrollPane;
	private JTable table;
	private ChunkReader reader;
	private ChunkModel model;

	// The minimum thumb height - it must never be smaller than this.
	private int MINIMUM_THUMB_HEIGHT = 20;
	private int THUMB_WIDTH = 10;

	/**
	 * Constructor.
	 * 
	 * @param slider
	 * @param scrollPane
	 * @param table
	 * @param reader
	 * @param model
	 */
	public FVSliderUI(JSlider slider, JScrollPane scrollPane, JTable table, ChunkReader reader, ChunkModel model) {
		super(slider);
		this.scrollPane = scrollPane;
		this.table = table;
		this.reader = reader;
		this.model = model;
	}

	/**
	 * This is the method that the base class uses to determine thumb size. We override so it
	 * can be determined by the size of the table and the viewport.
	 */
	@Override
	protected void calculateThumbSize() {
		
		super.calculateThumbSize();
		
		// Average the number of bytes in a row to get a reasonable row-to-byte factor.
		long fileSize;
		try {
			fileSize = reader.getFileSize();
		}
		catch (IOException e) {
			Msg.error(this,  "error reading file size: " + e);
			return;
		}
		
		int rows = table.getRowCount();
		if (rows == 0) {
			return;
		}
		long bytesInView = 0;
		Iterator<Chunk> iter = model.iterator();
		while (iter.hasNext()) {
			Chunk chunk = iter.next();
			bytesInView += (chunk.end - chunk.start);
		}
		long bytesPerLine = bytesInView / rows;
		long totalLinesInFile = fileSize / bytesPerLine;

		if (scrollPane.getViewport() != null) {
			float viewableRatio;
			viewableRatio = (float) scrollPane.getViewport().getHeight() / totalLinesInFile;
			float thumbHeight = viewableRatio * table.getRowHeight();
			thumbRect.setSize(THUMB_WIDTH, MINIMUM_THUMB_HEIGHT + (int) thumbHeight);
		}		
	}
}
