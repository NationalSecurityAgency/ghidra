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

/**
 * Collects the {@code stat} fields common to UNIX platforms
 * 
 * <p>
 * See a UNIX manual for the exact meaning of each field.
 * 
 * <p>
 * TODO: Should this be parameterized with T?
 * 
 * <p>
 * TODO: Are these specific to Linux, or all UNIX?
 */
public class EmuUnixFileStat {

	/**
	 * The mode bit indicating read permission
	 */
	public static final int MODE_R = 04;
	/**
	 * The mode bit indicating write permission
	 */
	public static final int MODE_W = 02;
	/**
	 * The mode bit indicating execute permission
	 */
	public static final int MODE_X = 01;

	public long st_dev;
	public long st_ino;
	public int st_mode;
	public long st_nlink;
	public int st_uid;
	public int st_gid;
	public long st_rdev;
	public long st_size;
	public long st_blksize;
	public long st_blocks;

	public long st_atim_sec;
	public long st_atim_nsec;
	public long st_mtim_sec;
	public long st_mtim_nsec;
	public long st_ctim_sec;
	public long st_ctim_nsec;

	/**
	 * Check if the given user has the requested permissions on the file described by this stat
	 * 
	 * @param req the requested permissions
	 * @param user the user requesting permission
	 * @return true if permitted, false if denied
	 */
	public boolean hasPermissions(int req, EmuUnixUser user) {
		// TODO: Care to simulate 'root'?
		if ((st_mode & req) == req) {
			return true;
		}
		if (((st_mode >> 6) & req) == req && user.uid == st_uid) {
			return true;
		}
		if (((st_mode >> 3) & req) == req && user.gids.contains(st_gid)) {
			return true;
		}
		return false;
	}
}
