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

import javax.sound.sampled.*;
import javax.sound.sampled.LineEvent.Type;
import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class AudioPlayer implements Playable, LineListener {

	private static final Icon AUDIO_ICON = new GIcon("icon.data.type.audio.player");

	// This currently only allows one clip to be played for the entire application, which seems
	// good enough.  This variable is currently synchronized by the Swing thread.
	private static volatile Clip currentClip;

	private byte[] bytes;

	public AudioPlayer(byte[] bytes) {
		this.bytes = bytes;
	}

	@Override
	public Icon getImageIcon() {
		return AUDIO_ICON;
	}

	@Override
	public void clicked(MouseEvent event) {

		// any new request should stop any previous clip being played
		if (currentClip != null) {
			currentClip.stop();
			currentClip = null; // this field is also updated when the sound thread calls back
			return;
		}

		try (AudioInputStream stream =
			AudioSystem.getAudioInputStream(new ByteArrayInputStream(bytes))) {
			Clip clip = AudioSystem.getClip();
			currentClip = clip;
			clip.addLineListener(this);
			clip.open(stream);
			clip.start();
		}
		catch (UnsupportedAudioFileException | IOException | LineUnavailableException e) {
			Msg.debug(this, "Unable to play audio", e);
		}
	}

	@Override
	public void update(LineEvent event) {
		LineEvent.Type eventType = event.getType();

		if (eventType != Type.STOP && eventType != Type.CLOSE) {
			return;
		}

		if (event.getSource() instanceof Clip clip) {
			clip.removeLineListener(this);
			clip.close();
			Swing.runNow(() -> {
				if (currentClip == clip) {
					currentClip = null;
				}
			});
		}
	}
}
