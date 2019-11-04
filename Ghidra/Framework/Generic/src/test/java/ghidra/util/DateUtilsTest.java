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
package ghidra.util;

import static org.junit.Assert.*;

import java.util.Date;

import org.junit.Test;

public class DateUtilsTest {

	@Test
	public void testFormatDate() {
		Date date = new Date(1572896586687L);
		assertEquals("11/04/2019", DateUtils.formatDate(date));
	}

	@Test
	public void testFormatDateTime() {
		Date date = new Date(1572896586687L);
		assertEquals("Nov 04, 2019 02:43 PM", DateUtils.formatDateTimestamp(date));
	}

	@Test
	public void testFormatDuration() {
		assertEquals("0 secs", DateUtils.formatDuration(100));
		assertEquals("0 secs", DateUtils.formatDuration(DateUtils.MS_PER_SEC - 1));
		assertEquals("1 secs", DateUtils.formatDuration(DateUtils.MS_PER_SEC));
		assertEquals("1 secs", DateUtils.formatDuration(DateUtils.MS_PER_SEC + 1));
		assertEquals("59 secs", DateUtils.formatDuration(DateUtils.MS_PER_MIN - 1));
		assertEquals("1 mins, 0 secs", DateUtils.formatDuration(DateUtils.MS_PER_MIN));
		assertEquals("1 mins, 1 secs",
			DateUtils.formatDuration(DateUtils.MS_PER_MIN + DateUtils.MS_PER_SEC));
		assertEquals("23 hours, 59 mins, 59 secs",
			DateUtils.formatDuration(DateUtils.MS_PER_DAY - 1));
		assertEquals("1 days, 0 hours, 0 mins, 0 secs",
			DateUtils.formatDuration(DateUtils.MS_PER_DAY));
		assertEquals("1 days, 0 hours, 0 mins, 0 secs",
			DateUtils.formatDuration(DateUtils.MS_PER_DAY + 1));
	}
}
