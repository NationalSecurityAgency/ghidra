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
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;

import ghidra.framework.LoggingInitialization;
import ghidra.util.Msg;
import ghidra.util.Swing;
import log.LogListener;
import log.LogPanelAppender;

public class AgentWindow extends JFrame implements WindowListener, LogListener {
	public static final int MAX_LOG_CHARS = 100000;

	protected final JTextArea logArea = new JTextArea();
	protected final JScrollPane logScroll = new JScrollPane(logArea);

	public AgentWindow(String title, SocketAddress localAddress) {
		super(title);
		setLayout(new BorderLayout());
		addWindowListener(this);
		add(new JLabel("<html>This agent is listening at <b>" + localAddress +
			"</b>. Close this window to terminate it.</html>"), BorderLayout.NORTH);
		logArea.setEditable(false);
		logArea.setFont(Font.decode(Font.MONOSPACED));
		logArea.setAutoscrolls(true);
		logScroll.setAutoscrolls(true);
		add(logScroll);
		setMinimumSize(new Dimension(400, 300));
		setVisible(true);

		System.setProperty("log4j.configuration", "agent.log4j.xml");
		LoggingInitialization.initializeLoggingSystem();
		LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
		Configuration config = ctx.getConfiguration();
		Appender appender = config.getAppender("logPanel");
		if (!(appender instanceof LogPanelAppender)) {
			Msg.error(this, "Couldn't find LogPanelAppender instance in the Log4j context. " +
				"Nothing will be logged to the agent's window.");
		}
		else {
			LogPanelAppender logPanelAppender = (LogPanelAppender) appender;
			logPanelAppender.setLogListener(this);
		}
	}

	@Override
	public void messageLogged(String message, boolean isError) {
		String fMessage = isError ? "<font color=\"red\">" + message + "</font>" : message;
		Swing.runIfSwingOrRunLater(() -> {
			String allText = logArea.getText() + fMessage + "\n";
			logArea.setText(
				allText.substring(Math.max(0, allText.length() - MAX_LOG_CHARS), allText.length()));
			JScrollBar vScroll = logScroll.getVerticalScrollBar();
			vScroll.setValue(vScroll.getMaximum());
		});
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
