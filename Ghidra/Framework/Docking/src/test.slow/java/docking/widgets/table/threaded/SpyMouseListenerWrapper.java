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
package docking.widgets.table.threaded;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import ghidra.docking.spy.SpyEventRecorder;

public class SpyMouseListenerWrapper implements MouseListener {

	private MouseListener delegate;
	private SpyEventRecorder recorder;

	public SpyMouseListenerWrapper(MouseListener l, SpyEventRecorder recorder) {
		this.delegate = l;
		this.recorder = recorder;
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		recorder.record("Swing mouseClicked() - count=" + e.getClickCount());
		delegate.mouseClicked(e);
	}

	@Override
	public void mousePressed(MouseEvent e) {
		recorder.record("Swing mousePressed() - count=" + e.getClickCount());
		delegate.mousePressed(e);
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		recorder.record("Swing mouseReleased() - count=" + e.getClickCount());
		delegate.mouseReleased(e);
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		delegate.mouseEntered(e);
	}

	@Override
	public void mouseExited(MouseEvent e) {
		delegate.mouseExited(e);
	}

}
