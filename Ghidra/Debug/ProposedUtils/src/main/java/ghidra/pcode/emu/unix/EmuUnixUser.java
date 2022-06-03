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
package ghidra.pcode.emu.unix;

import java.util.Collection;
import java.util.Set;

/**
 * A simulated UNIX user
 */
public class EmuUnixUser {
	/**
	 * The default (root?) user
	 */
	public static final EmuUnixUser DEFAULT_USER = new EmuUnixUser(0, Set.of());

	public final int uid;
	public final Collection<Integer> gids;

	/**
	 * Construct a new user
	 * 
	 * @param uid the user's uid
	 * @param gids the user's gids
	 */
	public EmuUnixUser(int uid, Collection<Integer> gids) {
		this.uid = uid;
		this.gids = gids;
	}
}
