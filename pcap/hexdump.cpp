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

#include "pcap/hexdump.hpp"
#include "util/throw_assert.hpp"

#include <sstream>

//namespace hex_dump {

std::string hexHeader()
{
    return "|    0    |    1    |    2    |    3    | ";
}

std::string printableHeader()
{
    return "| 0  | 1  | 2  | 3  |";
}

// Only translates up to 16 bytes. Always returns a string of 42 chars.
std::string binaryToHex(const uint8_t *data, size_t len)
{
    static_assert(kLineLength == 16, "Printing code needs to be updated to match kLineLength.");

    RT_ASSERT(len > 0 && len <= kLineLength, "len must be between 1 and 16 inclusive");
    std::string output_str("|         |         |         |         | ");
    auto putHexChar = [&output_str](uint8_t data, size_t offset)
        {
            constexpr char kHexTable[] = "0123456789abcdef";
            output_str.at(offset) = kHexTable[data / 16];
            output_str.at(offset+1) = kHexTable[data % 16];
        };

//  std::string output("|0011 2233|4455 6677|8899 1011|1213 1415| ");
//                      0123456789012345678901234567890123456789
    switch (len) {
        case 16:
            putHexChar(data[15], 38);
        case 15:
            putHexChar(data[14], 36);
        case 14:
            putHexChar(data[13], 33);
        case 13:
            putHexChar(data[12], 31);
        case 12:
            putHexChar(data[11], 28);
        case 11:
            putHexChar(data[10], 26);
        case 10:
            putHexChar(data[9], 23);
        case 9:
            putHexChar(data[8], 21);
        case 8:
            putHexChar(data[7], 18);
        case 7:
            putHexChar(data[6], 16);
        case 6:
            putHexChar(data[5], 13);
        case 5:
            putHexChar(data[4], 11);
        case 4:
            putHexChar(data[3], 8);
        case 3:
            putHexChar(data[2], 6);
        case 2:
            putHexChar(data[1], 3);
        case 1:
            putHexChar(data[0], 1);
            break;
        default:
            RT_THROW("Invalid len");
    }

    return output_str;
}

std::string binaryToPrintable(const uint8_t *data, size_t len)
{
    static_assert(kLineLength == 16, "Printing code needs to be updated to match kLineLength.");

    RT_ASSERT(len > 0 && len <= kLineLength, "len must be between 1 and 16 inclusive");
    std::string output_str("|    |    |    |    |");
    auto putPrintableChar = [&output_str](uint8_t data, size_t offset)
        {
            if (data < ' ' || data > '~') {
                output_str.at(offset) = '@';
            } else {
                output_str.at(offset) = data;
            }
        };

//  std::string output("|    |    |    |    |");
//                      01234567890123456789
    switch (len) {
        case 16:
            putPrintableChar(data[15], 19);
        case 15:
            putPrintableChar(data[14], 18);
        case 14:
            putPrintableChar(data[13], 17);
        case 13:
            putPrintableChar(data[12], 16);
        case 12:
            putPrintableChar(data[11], 14);
        case 11:
            putPrintableChar(data[10], 13);
        case 10:
            putPrintableChar(data[9], 12);
        case 9:
            putPrintableChar(data[8], 11);
        case 8:
            putPrintableChar(data[7], 9);
        case 7:
            putPrintableChar(data[6], 8);
        case 6:
            putPrintableChar(data[5], 7);
        case 5:
            putPrintableChar(data[4], 6);
        case 4:
            putPrintableChar(data[3], 4);
        case 3:
            putPrintableChar(data[2], 3);
        case 2:
            putPrintableChar(data[1], 2);
        case 1:
            putPrintableChar(data[0], 1);
            break;
        default:
            RT_THROW("Invalid len");
    }

    return output_str;
}

/**
 * @brief Dump a binary block of memory to a string, with hex and alpha
 *    representations.
 * Format:
 *                     (HEX)                        (PRINTABLE)
 *   |    0    |    1    |    2    |    3    | | 0  | 1  | 2  | 3  |
 *   |0123 4567|0123 4567|0123 4567|0123 4567| |0123|0123|0123|0123|
 */
std::string binaryToString(const uint8_t *data, size_t len)
{
    std::ostringstream oss;

    // Print out each 16 bytes.
    while (len > 0) {
        size_t len_to_print = std::min(kLineLength, len);
        oss << binaryToHex(data, len_to_print) << binaryToPrintable(data, len_to_print) << std::endl;
        len -= len_to_print;
        data += len_to_print;
    }

    return oss.str();
}

//} // namespace hex_dump
