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

public class AudioPlayer implements Playable, LineListener {

	private static final Icon AUDIO_ICON = new GIcon("icon.data.type.audio.player");

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
		try (AudioInputStream stream =
			AudioSystem.getAudioInputStream(new ByteArrayInputStream(bytes))) {
			Clip clip = AudioSystem.getClip();
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
		}
	}
}
