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

import java.util.Date;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class DateUtilsTest extends AbstractGenericTest {

	public DateUtilsTest() {
		// nada
	}

	/**
	 * This test was moved here from DateUtils.main()
	 */
	//@Test
	public void testHolidays() {
		for (int year = 2012; year < 2020; year++) {
			List<Date> holidays = DateUtils.getHolidays(year);
			for (Date date : holidays) {
				System.out.println(DateUtils.formatDate(date));
			}
		}
	}

	@Test
	public void testFormatDuration() {
		Assert.assertEquals("0 secs", DateUtils.formatDuration(100));
		Assert.assertEquals("0 secs", DateUtils.formatDuration(DateUtils.MS_PER_SEC - 1));
		Assert.assertEquals("1 secs", DateUtils.formatDuration(DateUtils.MS_PER_SEC));
		Assert.assertEquals("1 secs", DateUtils.formatDuration(DateUtils.MS_PER_SEC + 1));
		Assert.assertEquals("59 secs", DateUtils.formatDuration(DateUtils.MS_PER_MIN - 1));
		Assert.assertEquals("1 mins, 0 secs", DateUtils.formatDuration(DateUtils.MS_PER_MIN));
		Assert.assertEquals("1 mins, 1 secs",
			DateUtils.formatDuration(DateUtils.MS_PER_MIN + DateUtils.MS_PER_SEC));
		Assert.assertEquals("23 hours, 59 mins, 59 secs",
			DateUtils.formatDuration(DateUtils.MS_PER_DAY - 1));
		Assert.assertEquals("1 days, 0 hours, 0 mins, 0 secs",
			DateUtils.formatDuration(DateUtils.MS_PER_DAY));
		Assert.assertEquals("1 days, 0 hours, 0 mins, 0 secs",
			DateUtils.formatDuration(DateUtils.MS_PER_DAY + 1));
	}

}
