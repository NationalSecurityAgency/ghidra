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
package ghidra.app.plugin.core.byteviewer;

import java.math.BigInteger;

import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.nav.LocationMemento;
import ghidra.framework.options.SaveState;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class ByteViewerLocationMemento extends LocationMemento {
	protected static final String BLOCK_NUM = "Block Num";
	protected static final String BLOCK_OFFSET = "Block Offset";

	private final ViewerPosition viewerPosition;
	private final int blockNum;
	private final BigInteger blockOffset;
	private int column;

	public ByteViewerLocationMemento(Program program, ProgramLocation location, int blockNum,
			BigInteger blockOffset, int column, ViewerPosition viewerPosition) {
		super(program, location);
		this.blockNum = blockNum;
		this.blockOffset = blockOffset;
		this.viewerPosition = viewerPosition;
		this.column = column;
	}

	public ByteViewerLocationMemento(SaveState saveState, Program[] programs) {
		super(saveState, programs);
		blockNum = saveState.getInt(BLOCK_NUM, 0);
		blockOffset = new BigInteger(saveState.getString(BLOCK_OFFSET, "0"));
		int index = saveState.getInt("INDEX", 0);
		int yOffset = saveState.getInt("Y_OFFSET", 0);
		int xOffset = saveState.getInt("X_OFFSET", 0);
		viewerPosition = new ViewerPosition(index, xOffset, yOffset);
	}

	public BigInteger getBlockOffset() {
		return blockOffset;
	}

	public ViewerPosition getViewerPosition() {
		return viewerPosition;
	}

	public int getBlockNum() {
		return blockNum;
	}

	public int getColumn() {
		return column;
	}

	@Override
	public void saveState(SaveState saveState) {
		super.saveState(saveState);
		saveState.putInt("INDEX", viewerPosition.getIndexAsInt());
		saveState.putInt("Y_OFFSET", viewerPosition.getYOffset());
		saveState.putInt("X_OFFSET", viewerPosition.getYOffset());
		saveState.putInt(BLOCK_NUM, blockNum);
		if (blockOffset != null) {
			saveState.putString(BLOCK_OFFSET, blockOffset.toString());
		}
	}
}
