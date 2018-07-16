/*
 * This source code is distributed under the MIT License.
 *
 * Copyright 2018 Ray Chow (rycshaw@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#pragma once

#include <sstream>

namespace hexdump {

static constexpr size_t kLineLength = 16;

std::string hexHeader();

std::string printableHeader();

// Only translates up to 16 bytes. Always returns a string of 42 chars.
std::string binaryToHex(const uint8_t *data, size_t len);

std::string binaryToPrintable(const uint8_t data, size_t len);

/**
 * @brief Dump a binary block of memory to a string, with hex and alpha
 *    representations.
 * Format:
 *                     (HEX)                        (PRINTABLE)
 *   |    0    |    1    |    2    |    3    | | 0  | 1  | 2  | 3  |
 *   |0123 4567|0123 4567|0123 4567|0123 4567| |0123|0123|0123|0123|
 */
std::string binaryToString(const uint8_t *data, size_t len);

} // namespace hexdump
