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
package log;

import java.io.Serializable;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.*;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.*;
import org.apache.logging.log4j.core.layout.PatternLayout;

/**
 * Log4j appender that writes messages to the log panel in the main Ghidra window. 
 * This is configured in the various log4j configuration files 
 * (generic.log4j.xml, generic.logjdev.xml, etc...).
 * <p>
 * Note: This appender is created when the log4j configuration is processed and will 
 * start receiving log messages immediately. These messages will be dropped on the 
 * floor however, until an implementation of {@link LogListener} is instantiated and 
 * the {@link #setLogListener(LogListener)} method is invoked.
 */
@Plugin(name = "LogPanelAppender", category = "Core", elementType = "appender", printObject = true)
public class LogPanelAppender extends AbstractAppender {

	// The panel all messages will be displayed in. This must be set or incoming
	// log messages will be ignored.
	private LogListener logListener;

	protected LogPanelAppender(String name, Filter filter, Layout<? extends Serializable> layout) {
		super(name, filter, layout, true, Property.EMPTY_ARRAY);
	}

	@Override
	public void append(LogEvent event) {

		if (logListener == null) {
			return;
		}
		
		// An error is identified as any log that is tagged ERROR or FATAL.
		boolean isError = event.getLevel().isMoreSpecificThan(Level.ERROR);
		String message = event.getMessage().getFormattedMessage();
		logListener.messageLogged(message, isError);
	}

	@PluginFactory
	public static LogPanelAppender createAppender(@PluginAttribute("name") String name,
			@PluginElement("Layout") Layout<? extends Serializable> layout,
			@PluginElement("Filter") final Filter filter,
			@PluginAttribute("otherAttribute") String otherAttribute) {
		if (name == null) {
			LOGGER.error("No name provided for LogPanelAppender");
			return null;
		}
		if (layout == null) {
			layout = PatternLayout.createDefaultLayout();
		}
		return new LogPanelAppender(name, filter, layout);
	}

	public void setLogListener(LogListener listener) {
		// Note: this method may be called multiple times in a single JVM instance, such as 
		//       when testing.
		this.logListener = listener;
	}
}
