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
package ghidra.app.util.pcode;

import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.program.model.lang.Language;

public class StringPcodeFormatter
		extends AbstractPcodeFormatter<String, StringPcodeFormatter.ToStringAppender> {
	private static final String EOL = System.getProperty("line.separator");

	private int maxDisplayLines = 0; // no limit by default
	private boolean displayRawPcode = false;

	@Override
	protected ToStringAppender createAppender(Language language, boolean indent) {
		return new ToStringAppender(language, indent);
	}

	@Override
	public boolean isFormatRaw() {
		return displayRawPcode;
	}

	@Override
	protected FormatResult formatOpTemplate(ToStringAppender appender, OpTpl op) {
		if (maxDisplayLines > 0 && appender.lineCount >= maxDisplayLines) {
			return FormatResult.TERMINATE;
		}
		FormatResult result = super.formatOpTemplate(appender, op);
		appender.appendEndOfLine();
		return result;
	}

	static class ToStringAppender extends AbstractAppender<String> {
		private final StringBuffer buf = new StringBuffer();
		private int lineCount = 0;

		public ToStringAppender(Language language, boolean labeled) {
			super(language, labeled);
		}

		protected void appendEndOfLine() {
			if (buf.length() != 0) {
				buf.append(EOL);
			}
			lineCount++;
		}

		@Override
		protected void appendString(String string) {
			buf.append(string);
		}

		@Override
		public String finish() {
			return buf.toString();
		}
	}
}
