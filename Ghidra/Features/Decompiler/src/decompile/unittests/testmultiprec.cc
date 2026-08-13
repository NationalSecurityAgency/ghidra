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
#include "test.hh"
#include "multiprecision.hh"

namespace ghidra {

static uint8 num1[2] = { 0xffffffffffffffff, 0xffffffffffffffff };
static uint8 denom1[2] = { 1, 0 };
static uint8 num2[2] = { 0x89a732a9fb157c4d, 0x4eada2039e48443e };
static uint8 denom2[2] = { 0xbabf3b71, 0 };
static uint8 num3[2] = { 0xf7df0315d584ad8d, 0xb9d55c0d1d5cfbbd };
static uint8 denom3[2] = { 0x8aa797dbccee6e96, 0x646be9 };
static uint8 a[2] = { 0x1a309a9df2ce836a, 0xd66f2248906d1bdf };
static uint8 b[2] = { 0xf6c190704eb1763e, 0xa05c42212dfba7c6 };

TEST(multiprec_udiv) {
  uint8 q[2];
  uint8 r[2];

  udiv128(num1, denom1, q, r);
  ASSERT_EQUALS(q[0],0xffffffffffffffff);
  ASSERT_EQUALS(q[1],0xffffffffffffffff);
  ASSERT_EQUALS(r[0],0);
  ASSERT_EQUALS(r[1],0);

  udiv128(num2, denom2, q, r);
  ASSERT_EQUALS(q[0], 0x2a21eef2058d7e9a);
  ASSERT_EQUALS(q[1], 0x6bdaed99);
  ASSERT_EQUALS(r[0], 0x928d1c53);
  ASSERT_EQUALS(r[1], 0);

  udiv128(num2,num1,q,r);
  ASSERT_EQUALS(q[0], 0);
  ASSERT_EQUALS(q[1], 0);
  ASSERT_EQUALS(r[0],num2[0]);
  ASSERT_EQUALS(r[1],num2[1]);

  udiv128(num3,denom3,q,r);
  ASSERT_EQUALS(q[0], 0x1d9bc949e24);
  ASSERT_EQUALS(q[1], 0);
  ASSERT_EQUALS(r[0], 0x2e78197dc5048c75);
  ASSERT_EQUALS(r[1], 0x24d9cc);
}

TEST(multiprec_add) {
  uint8 res[2];
  add128(a,b,res);
  ASSERT_EQUALS(res[0], 0x10f22b0e417ff9a8);
  ASSERT_EQUALS(res[1], 0x76cb6469be68c3a6);
}

TEST(multiprec_sub) {
  uint8 res[2];
  subtract128(a,b,res);
  ASSERT_EQUALS(res[0], 0x236F0A2DA41D0D2C);
  ASSERT_EQUALS(res[1], 0x3612E02762717418);
}

TEST(multiprec_left) {
  uint8 res[2];
  leftshift128(num2, res, 51);
  ASSERT_EQUALS(res[0], 0xe268000000000000);
  ASSERT_EQUALS(res[1], 0x21f44d39954fd8ab);
}

TEST(multiprec_less) {
  ASSERT(!uless128(a,a));
  ASSERT(uless128(num2,num3));
  ASSERT(uless128(denom1,denom2));
  ASSERT(ulessequal128(a,a));
  ASSERT(ulessequal128(num2,num3));
  ASSERT(ulessequal128(denom2,denom2));
}

}  // End namespace ghidra
