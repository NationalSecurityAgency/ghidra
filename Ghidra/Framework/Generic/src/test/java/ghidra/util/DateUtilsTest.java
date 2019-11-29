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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.junit.Test;

public class DateUtilsTest {

	@Test
	public void testFormatDate() {
		Date date = new Date(1572896586687L);
		assertEquals("11/04/2019", DateUtils.formatDate(date));
	}

	@Test
	public void testFormatDateTime() throws ParseException {
		SimpleDateFormat format = new SimpleDateFormat("MMM dd, yyyy hh:mm a");
		String dateString = "Nov 04, 2019 02:43 PM";
		Date date = format.parse(dateString);
		assertEquals(dateString, DateUtils.formatDateTimestamp(date));
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

	@Test
	public void testNormalize() {
		long now = System.currentTimeMillis();
		long threeHourOffset = 3 * (60 * 60 * 1000);
		long future = now + threeHourOffset;
		Date nowDate = new Date(now);
		Date futureDate = new Date(future);

		assertNotEquals(nowDate, futureDate);
		Date nowNormalized = DateUtils.normalizeDate(nowDate);
		Date futureNormalized = DateUtils.normalizeDate(futureDate);
		assertEquals(nowNormalized, futureNormalized);
	}

	@Test
	public void testGetDaysBetween() {

		long now = System.currentTimeMillis();
		int days = 3;
		long threeDaysOffset = days * (24 * 60 * 60 * 1000);
		long future = now + threeDaysOffset;

		Date nowDate = new Date(now);
		Date futureDate = new Date(future);
		int daysBetween = DateUtils.getDaysBetween(nowDate, futureDate);
		assertEquals(days, daysBetween);
	}

	@Test
	public void testGetDaysBetween_SameDay() {

		long now = System.currentTimeMillis();
		Date nowDate = new Date(now);
		int daysBetween = DateUtils.getDaysBetween(nowDate, nowDate);
		assertEquals(0, daysBetween);
	}

	@Test
	public void testGetDaysBetween_MostRecentDateFirst() {

		long now = System.currentTimeMillis();
		int days = 3;
		long threeDaysOffset = days * (24 * 60 * 60 * 1000);
		long future = now + threeDaysOffset;

		Date nowDate = new Date(now);
		Date futureDate = new Date(future);
		int daysBetween = DateUtils.getDaysBetween(futureDate, nowDate);
		assertEquals(days, daysBetween);
	}

	@Test
	public void testGetBusinessDaysBetween() {

		int november = 10;
		Date friday = DateUtils.getDate(2019, november, 22);
		Date monday = DateUtils.getDate(2019, november, 25);
		int daysBetween = DateUtils.getBusinessDaysBetween(friday, monday);
		assertEquals(1, daysBetween);
	}
}
