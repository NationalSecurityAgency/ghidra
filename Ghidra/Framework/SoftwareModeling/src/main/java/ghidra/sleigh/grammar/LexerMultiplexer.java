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
package ghidra.sleigh.grammar;

import java.util.*;

import org.antlr.runtime.Token;
import org.antlr.runtime.TokenSource;

public class LexerMultiplexer implements TokenSource {

	protected final TokenSource[] modes;
	private final Deque<Integer> stack;

	private final Set<Integer> channels;

	public LexerMultiplexer(TokenSource... modes) {
		this.modes = modes;

		this.stack = new LinkedList<>();
		this.stack.push(0);

		this.channels = new HashSet<>();
		this.channels.add(Token.DEFAULT_CHANNEL);
	}

	@Override
	public String getSourceName() {
		StringBuilder sb = new StringBuilder();
		sb.append("Mux[");
		for (int i = 0; i < modes.length; i++) {
			if (i != 0) {
				sb.append(",");
			}
			sb.append(i);
			sb.append(":");
			sb.append(modes[i].getSourceName());
		}
		sb.append("]");
		return sb.toString();
	}

	@Override
	public Token nextToken() {
		Integer mode = stack.peekFirst();
		TokenSource src = modes[mode];
		Token t;
		do {
			t = src.nextToken();
			//System.out.println("Token(" + mode + "," + src.getSourceName() + "): " + t);
		}
		while (!channels.contains(t.getChannel()));
		return t;
	}

	public int popMode() {
		//System.out.println("Popping");
		return this.stack.pop();
	}

	public void pushMode(int mode) {
		//System.out.println("Pushing: " + mode);
		this.stack.push(mode);
	}

	public void setMode(int mode) {
		popMode();
		pushMode(mode);
	}

	public void channelOn(int channel) {
		this.channels.add(channel);
	}

	public void channelOff(int channel) {
		this.channels.remove(channel);
	}
}
