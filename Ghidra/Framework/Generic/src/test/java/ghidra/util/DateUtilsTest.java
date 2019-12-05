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

import java.text.SimpleDateFormat;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

public class DateUtilsTest {

	private String testDateString;
	private Date testDate;

	@Before
	public void setUp() throws Exception {
		SimpleDateFormat format = new SimpleDateFormat("MMM dd, yyyy hh:mm a");
		testDateString = "Nov 04, 2019 02:43 PM";
		testDate = format.parse(testDateString);
	}

	@Test
	public void testFormatDate() {
		assertEquals("11/04/2019", DateUtils.formatDate(testDate));
	}

	@Test
	public void testFormatDateTime() {
		assertEquals(testDateString, DateUtils.formatDateTimestamp(testDate));
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
		long time = testDate.getTime();
		long threeHourOffset = 3 * (60 * 60 * 1000);
		long future = time + threeHourOffset;
		Date nowDate = new Date(time);
		Date futureDate = new Date(future);

		assertNotEquals(nowDate, futureDate);
		Date nowNormalized = DateUtils.normalizeDate(nowDate);
		Date futureNormalized = DateUtils.normalizeDate(futureDate);
		assertEquals(nowNormalized, futureNormalized);
	}

	@Test
	public void testGetDaysBetween() {

		long time = testDate.getTime();
		int days = 3;
		long threeDaysOffset = days * (24 * 60 * 60 * 1000);
		long future = time + threeDaysOffset;

		Date nowDate = new Date(time);
		Date futureDate = new Date(future);
		int daysBetween = DateUtils.getDaysBetween(nowDate, futureDate);
		assertEquals(days, daysBetween);
	}

	@Test
	public void testGetDaysBetween_SameDay() {

		long time = testDate.getTime();
		Date date = new Date(time);
		int daysBetween = DateUtils.getDaysBetween(date, date);
		assertEquals(0, daysBetween);
	}

	@Test
	public void testGetDaysBetween_MostRecentDateFirst() {

		long time = testDate.getTime();
		int days = 3;
		long threeDaysOffset = days * (24 * 60 * 60 * 1000);
		long future = time + threeDaysOffset;

		Date nowDate = new Date(time);
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
