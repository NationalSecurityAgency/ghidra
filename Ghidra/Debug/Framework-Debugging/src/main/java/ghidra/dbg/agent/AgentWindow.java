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
package ghidra.dbg.agent;

import java.awt.*;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.net.SocketAddress;

import javax.swing.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;

public class AgentWindow extends JFrame implements WindowListener {
	public static final int MAX_LOG_CHARS = 10000;

	protected class WindowAppender extends AbstractAppender {
		protected WindowAppender() {
			super("agentAppender", null, null, true, Property.EMPTY_ARRAY);
		}

		@Override
		public void append(LogEvent event) {
			String allText = logArea.getText() + "\n" + event.getMessage().getFormattedMessage();
			logArea.setText(
				allText.substring(Math.max(0, allText.length() - MAX_LOG_CHARS), allText.length()));
			// TODO: Scroll to bottom
		}
	}

	protected final JTextArea logArea = new JTextArea();
	protected final JScrollPane logScroll = new JScrollPane(logArea);

	public AgentWindow(String title, SocketAddress localAddress) {
		super(title);
		setLayout(new BorderLayout());
		addWindowListener(this);
		add(new JLabel("<html>This agent is listening at <b>" + localAddress +
			"</b>. Close this window to terminate it.</html>"), BorderLayout.NORTH);
		logArea.setEditable(false);
		logArea.setFont(Font.getFont(Font.MONOSPACED));
		logArea.setAutoscrolls(true);
		logScroll.setAutoscrolls(true);
		add(logScroll);
		setMinimumSize(new Dimension(400, 300));
		setVisible(true);

		LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
		ctx.getConfiguration().addAppender(new WindowAppender());
	}

	@Override
	public void windowOpened(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowClosing(WindowEvent e) {
		System.out.println("User closed agent window. Exiting");
		System.exit(0);
	}

	@Override
	public void windowClosed(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowIconified(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowDeiconified(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowActivated(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowDeactivated(WindowEvent e) {
		// Dont' care
	}
}
