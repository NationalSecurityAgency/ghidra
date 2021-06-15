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
/// \file test.cc
/// \brief Unit tests for Ghidra C++ components.

#include "float.hh"
#include "opbehavior.hh"
#include "test.hh"

#include <cmath>
#include <cstdint>
#include <cstring>

#include <limits>
#include <vector>

// utility functions
float floatFromRawBits(uintb e) {
    float f;
    memcpy(&f, &e, 4);
    return f;
}

uintb floatToRawBits(float f) {
    uintb result = 0;
    memcpy(&result, &f, 4);
    return result;
}

double doubleFromRawBits(uintb e) {
    double f;
    memcpy(&f, &e, 8);
    return f;
}

uintb doubleToRawBits(double f) {
    uintb result = 0;
    memcpy(&result, &f, 8);
    return result;
}

// macros to preserve call site
#define ASSERT_FLOAT_ENCODING(f)                                                                                       \
    do {                                                                                                               \
        FloatFormat format(4);                                                                                         \
                                                                                                                       \
        uintb true_encoding = floatToRawBits(f);                                                                       \
        uintb encoding = format.getEncoding(f);                                                                        \
                                                                                                                       \
        ASSERT_EQUALS(true_encoding, encoding);                                                                        \
    } while (0);

#define ASSERT_DOUBLE_ENCODING(f)                                                                                      \
    do {                                                                                                               \
        FloatFormat format(8);                                                                                         \
                                                                                                                       \
        uintb true_encoding = doubleToRawBits(f);                                                                      \
        uintb encoding = format.getEncoding(f);                                                                        \
                                                                                                                       \
        ASSERT_EQUALS(true_encoding, encoding);                                                                        \
    } while (0);

//// FloatFormat tests

static std::vector<float> float_test_values{
    -0.0f,
    +0.0f,
    -1.0f,
    +1.0f,

    -1.234f,
    +1.234f,

    -std::numeric_limits<float>::denorm_min(),
    std::numeric_limits<float>::denorm_min(),

    std::numeric_limits<float>::min() - std::numeric_limits<float>::denorm_min(),
    std::numeric_limits<float>::min(),
    std::numeric_limits<float>::min() + std::numeric_limits<float>::denorm_min(),

    -std::numeric_limits<float>::min() + std::numeric_limits<float>::denorm_min(),
    -std::numeric_limits<float>::min(),
    -std::numeric_limits<float>::min() - std::numeric_limits<float>::denorm_min(),

    std::numeric_limits<float>::max(),

    std::numeric_limits<float>::quiet_NaN(),

    -std::numeric_limits<float>::infinity(),
    std::numeric_limits<float>::infinity()
};

static std::vector<int> int_test_values = {
    0, -1, 1, 1234, -1234, std::numeric_limits<int>::min(), std::numeric_limits<int>::max()
};

TEST(float_encoding_normal) {
    ASSERT_FLOAT_ENCODING(1.234);
    ASSERT_FLOAT_ENCODING(-1.234);
}

TEST(double_encoding_normal) {
    ASSERT_DOUBLE_ENCODING(1.234);
    ASSERT_DOUBLE_ENCODING(-1.234);
}

TEST(float_encoding_nan) {
    ASSERT_FLOAT_ENCODING(std::numeric_limits<float>::quiet_NaN());
    ASSERT_FLOAT_ENCODING(-std::numeric_limits<float>::quiet_NaN());
}

TEST(double_encoding_nan) {
    ASSERT_DOUBLE_ENCODING(std::numeric_limits<double>::quiet_NaN());
    ASSERT_DOUBLE_ENCODING(-std::numeric_limits<double>::quiet_NaN());
}

TEST(float_encoding_subnormal) {
    ASSERT_FLOAT_ENCODING(std::numeric_limits<float>::denorm_min());
    ASSERT_FLOAT_ENCODING(-std::numeric_limits<float>::denorm_min());
}

TEST(double_encoding_subnormal) {
    ASSERT_DOUBLE_ENCODING(std::numeric_limits<double>::denorm_min());
    ASSERT_DOUBLE_ENCODING(-std::numeric_limits<double>::denorm_min());
}

TEST(float_encoding_min_normal) {
    ASSERT_FLOAT_ENCODING(std::numeric_limits<float>::min());
    ASSERT_FLOAT_ENCODING(-std::numeric_limits<float>::min());
}

TEST(double_encoding_min_normal) {
    ASSERT_DOUBLE_ENCODING(std::numeric_limits<double>::min());
    ASSERT_DOUBLE_ENCODING(-std::numeric_limits<double>::min());
}

TEST(float_encoding_infinity) {
    ASSERT_FLOAT_ENCODING(std::numeric_limits<float>::infinity());
    ASSERT_FLOAT_ENCODING(-std::numeric_limits<float>::infinity());
}

TEST(double_encoding_infinity) {
    ASSERT_DOUBLE_ENCODING(std::numeric_limits<double>::infinity());
    ASSERT_DOUBLE_ENCODING(-std::numeric_limits<double>::infinity());
}

TEST(float_midpoint_rounding) {
    FloatFormat ff(4);
    // IEEE754 recommends "round to nearest even" for binary formats, like single and double
    // precision floating point.  It rounds to the nearest integer (significand) when unambiguous,
    // and to the nearest even on the midpoint.

    // There are 52 bits of significand in a double and 23 in a float.
    // Below we construct a sequence of double precision values to demonstrate each case
    // in rounding,

    // 		d0 - zeros in low 29 bits, round down
    // 		d1 - on the rounding midpoint with integer even integer part, round down
    //      d2 - just above the midpoint, round up
    double d0 = doubleFromRawBits(0x4010000000000000L);
    double d1 = doubleFromRawBits(0x4010000010000000L);
    double d2 = doubleFromRawBits(0x4010000010000001L);

    // 		d3 - zeros in low 29 bits, round down
    // 		d4 - on the rounding midpoint with integer part odd, round up
    //      d5 - just above the midpoint, round up
    double d3 = doubleFromRawBits(0x4010000020000000L);
    double d4 = doubleFromRawBits(0x4010000030000000L);
    double d5 = doubleFromRawBits(0x4010000030000001L);

    float f0 = (float)d0;
    float f1 = (float)d1;
    float f2 = (float)d2;
    float f3 = (float)d3;
    float f4 = (float)d4;
    float f5 = (float)d5;

    uintb e0 = ff.getEncoding(d0);
    uintb e1 = ff.getEncoding(d1);
    uintb e2 = ff.getEncoding(d2);
    uintb e3 = ff.getEncoding(d3);
    uintb e4 = ff.getEncoding(d4);
    uintb e5 = ff.getEncoding(d5);

    ASSERT_EQUALS(floatToRawBits(f0), e0);
    ASSERT_EQUALS(floatToRawBits(f1), e1);
    ASSERT_EQUALS(floatToRawBits(f2), e2);
    ASSERT_EQUALS(floatToRawBits(f3), e3);
    ASSERT_EQUALS(floatToRawBits(f4), e4);
    ASSERT_EQUALS(floatToRawBits(f5), e5);

    ASSERT_EQUALS(e0, e1);
    ASSERT_NOT_EQUALS(e1, e2);

    ASSERT_NOT_EQUALS(e3, e4);
    ASSERT_EQUALS(e4, e5);
}

// op tests

// generated 

TEST(float_opNan) {
    FloatFormat format(4);

    for(float f:float_test_values) {
        uintb true_result = isnan(f);
        uintb encoding = format.getEncoding(f);
        uintb result = format.opNan(encoding);

        ASSERT_EQUALS(true_result, result);
    }
}


TEST(float_opNeg) {
    FloatFormat format(4);

    for(float f:float_test_values) {
        uintb true_result = floatToRawBits(-f);
        uintb encoding = format.getEncoding(f);
        uintb result = format.opNeg(encoding);

        ASSERT_EQUALS(true_result, result);
    }
}


TEST(float_opAbs) {
    FloatFormat format(4);

    for(float f:float_test_values) {
        uintb true_result = floatToRawBits(abs(f));
        uintb encoding = format.getEncoding(f);
        uintb result = format.opAbs(encoding);

        ASSERT_EQUALS(true_result, result);
    }
}


TEST(float_opSqrt) {
    FloatFormat format(4);

    for(float f:float_test_values) {
        uintb true_result = floatToRawBits(sqrtf(f));
        uintb encoding = format.getEncoding(f);
        uintb result = format.opSqrt(encoding);

        ASSERT_EQUALS(true_result, result);
    }
}


TEST(float_opCeil) {
    FloatFormat format(4);

    for(float f:float_test_values) {
        uintb true_result = floatToRawBits(ceilf(f));
        uintb encoding = format.getEncoding(f);
        uintb result = format.opCeil(encoding);

        ASSERT_EQUALS(true_result, result);
    }
}


TEST(float_opFloor) {
    FloatFormat format(4);

    for(float f:float_test_values) {
        uintb true_result = floatToRawBits(floorf(f));
        uintb encoding = format.getEncoding(f);
        uintb result = format.opFloor(encoding);

        ASSERT_EQUALS(true_result, result);
    }
}


TEST(float_opRound) {
    FloatFormat format(4);

    for(float f:float_test_values) {
        uintb true_result = floatToRawBits(roundf(f));
        uintb encoding = format.getEncoding(f);
        uintb result = format.opRound(encoding);

        ASSERT_EQUALS(true_result, result);
    }
}


TEST(float_opInt2Float_size4) {
    FloatFormat format(4);

    for(int i:int_test_values) {
        uintb true_result = floatToRawBits((float)i);
        uintb result = format.opInt2Float(i, 4);

        ASSERT_EQUALS(true_result, result);
    }
}
// TODO other sized ints

TEST(float_to_double_opFloat2Float) {
    FloatFormat format(4);
    FloatFormat format8(8);

    for(float f:float_test_values) {
        uintb true_result = doubleToRawBits((double)f);
        uintb encoding = format.getEncoding(f);
        uintb result = format.opFloat2Float(encoding, format8);

        ASSERT_EQUALS(true_result, result);
    }
}

//  TODO float2float going the other direction, double_to_float_opFloat2Float


TEST(float_opTrunc_to_int) {
    FloatFormat format(4);
    FloatFormat format8(8);

    for(float f:float_test_values) {
        // avoid undefined behavior
        if((int64_t)f > std::numeric_limits<int>::max() || (int64_t)f < std::numeric_limits<int>::min())
            continue;
        uintb true_result = ((uintb)(int32_t)f) & 0xffffffff;
        uintb encoding = format.getEncoding(f);
        uintb result = format.opTrunc(encoding, 4);

        ASSERT_EQUALS(true_result, result);
    }
}

// TODO trunc to other sizes



TEST(float_opEqual) {
    FloatFormat format(4);

    for(float f1:float_test_values) {
        uintb encoding1 = format.getEncoding(f1);
        for(float f2:float_test_values) {
            uintb true_result = (f1==f2);
            uintb encoding2 = format.getEncoding(f2);
            uintb result = format.opEqual(encoding1, encoding2);

            ASSERT_EQUALS(true_result, result);
        }
    }
}


TEST(float_opNotEqual) {
    FloatFormat format(4);

    for(float f1:float_test_values) {
        uintb encoding1 = format.getEncoding(f1);
        for(float f2:float_test_values) {
            uintb true_result = (f1!=f2);
            uintb encoding2 = format.getEncoding(f2);
            uintb result = format.opNotEqual(encoding1, encoding2);

            ASSERT_EQUALS(true_result, result);
        }
    }
}


TEST(float_opLess) {
    FloatFormat format(4);

    for(float f1:float_test_values) {
        uintb encoding1 = format.getEncoding(f1);
        for(float f2:float_test_values) {
            uintb true_result = (f1<f2);
            uintb encoding2 = format.getEncoding(f2);
            uintb result = format.opLess(encoding1, encoding2);

            ASSERT_EQUALS(true_result, result);
        }
    }
}


TEST(float_opLessEqual) {
    FloatFormat format(4);

    for(float f1:float_test_values) {
        uintb encoding1 = format.getEncoding(f1);
        for(float f2:float_test_values) {
            uintb true_result = (f1<=f2);
            uintb encoding2 = format.getEncoding(f2);
            uintb result = format.opLessEqual(encoding1, encoding2);

            ASSERT_EQUALS(true_result, result);
        }
    }
}


TEST(float_opAdd) {
    FloatFormat format(4);

    for(float f1:float_test_values) {
        uintb encoding1 = format.getEncoding(f1);
        for(float f2:float_test_values) {
            uintb true_result = floatToRawBits(f1+f2);
            uintb encoding2 = format.getEncoding(f2);
            uintb result = format.opAdd(encoding1, encoding2);

            ASSERT_EQUALS(true_result, result);
        }
    }
}


TEST(float_opDiv) {
    FloatFormat format(4);

    for(float f1:float_test_values) {
        uintb encoding1 = format.getEncoding(f1);
        for(float f2:float_test_values) {
            uintb true_result = floatToRawBits(f1/f2);
            uintb encoding2 = format.getEncoding(f2);
            uintb result = format.opDiv(encoding1, encoding2);

            ASSERT_EQUALS(true_result, result);
        }
    }
}


TEST(float_opMult) {
    FloatFormat format(4);

    for(float f1:float_test_values) {
        uintb encoding1 = format.getEncoding(f1);
        for(float f2:float_test_values) {
            uintb true_result = floatToRawBits(f1*f2);
            uintb encoding2 = format.getEncoding(f2);
            uintb result = format.opMult(encoding1, encoding2);

            ASSERT_EQUALS(true_result, result);
        }
    }
}


TEST(float_opSub) {
    FloatFormat format(4);

    for(float f1:float_test_values) {
        uintb encoding1 = format.getEncoding(f1);
        for(float f2:float_test_values) {
            uintb true_result = floatToRawBits(f1-f2);
            uintb encoding2 = format.getEncoding(f2);
            uintb result = format.opSub(encoding1, encoding2);

            ASSERT_EQUALS(true_result, result);
        }
    }
}

// end generated 
