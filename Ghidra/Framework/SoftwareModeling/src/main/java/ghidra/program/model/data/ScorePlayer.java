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
package ghidra.program.model.data;

import java.awt.event.MouseEvent;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.sound.midi.*;
import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * Plays a MIDI score
 */
public class ScorePlayer implements Playable, MetaEventListener {

	private static final Icon MIDI_ICON = new GIcon("icon.data.type.audio.player");
	private static final int END_OF_TRACK_MESSAGE = 47;
	
	// This currently only allows one sequence to be played for the entire application,
	// which seems good enough.  The MIDI instance variables are currently synchronized
	// by the Swing thread.
	private static volatile Sequencer currentSequencer;

	private byte[] bytes;

	public ScorePlayer(byte[] bytes) {
		this.bytes = bytes;
	}

	@Override
	public Icon getImageIcon() {
		return MIDI_ICON;
	}

	@Override
	public void clicked(MouseEvent event) {
		try {
			// Any new request should stop any previous sequence being played
			if (currentSequencer != null) {
				stop();
				return;
			}

			Sequencer sequencer = MidiSystem.getSequencer(true);
			sequencer.addMetaEventListener(this);
			sequencer.setLoopCount(0);
			sequencer.setSequence(MidiSystem.getSequence(new ByteArrayInputStream(bytes)));
			sequencer.open();
			currentSequencer = sequencer;
			currentSequencer.start();
		}
		catch (MidiUnavailableException | InvalidMidiDataException | IOException e) {
			Msg.error(this, "Unable to play score", e);
		}
	}

	@Override
	public void meta(MetaMessage message) {
		if (message.getType() == END_OF_TRACK_MESSAGE) {
			Swing.runNow(() -> stop());
		}
	}

	private void stop() {
		if (currentSequencer == null) {
			return;
		}
		currentSequencer.removeMetaEventListener(this);
		currentSequencer.stop();
		currentSequencer.close();
		currentSequencer = null;
	}
}
