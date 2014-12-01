<?php

namespace s9e\TextFormatter\Tests;

use PHPUnit_Framework_TestCase;
use s9e\Acl\BitPacker;

/**
* @covers s9e\Acl\BitPacker
*/
class BitPackerTest extends PHPUnit_Framework_TestCase
{
	/**
	* @dataProvider getMergeTests
	*/
	public function testMerge($strings, $expected)
	{
		$actual = BitPacker::merge($strings);
		$this->assertSame($expected, $actual);

		foreach ($strings as $string)
		{
			$this->assertContains($string, $actual);
		}
	}

	public function getMergeTests()
	{
		return [
			[
				['10000', '01001'],
				'100001001'
			],
			[
				['1111', '0000'],
				'11110000'
			],
			[
				['11110', '11000', '11100'],
				'1111000'
			],
			[
				['011', '011111', '11100'],
				'01111100'
			],
			[
				['11010', '10101', '01010', '10100'],
				'11010100'
			],
			[
				// This test doesn't target any specific code path. It just merges 2048 strings
				// (1536 unique strings) that are between 1 and 10 characters long. It ensures that
				// things don't go haywire when we try to merge many strings
				array_merge(
					array_map('decbin', range(0, 1023)),
					array_map(
						function ($i)
						{
							return sprintf('%010b', $i);
						},
						range(0, 1023)
					)
				),
				'1001111111001000000101011111101010000001011011111110110000001100001111001111000101000000111001111100011000010010100110010111100110100000101110000111001000100011000101110011111001010000101011011111010010000111010111100111100000100010011110110010000101010111101011100001010001111010111000110100011100110110010100101010110111011101100010001010111001011100101010010101110110101000100101110101101001111001101000101001110101111000111000100100100101100101101010101001011101111010001000010111101111100011000001110111111001100000001011111111110000000000110110101101100101011001101010101001110111011001100110001000100001101101001011001101110101001001111101011000011110100110000110101001101111101011000001110100001001110001011000111110100100000110111111100100000001111000011000100110100110100111101110100001000110111101101100011001001110011011000110110000101100111101000100011100101110001101001001011011011110010010001010110001011101001110011101001010001101110111001001100101011010101110110111001100100011010101110011101000110011100101010001101011101001010011011011010010010011011011110110010001100110101000101111100101000001101011111001110000101001000101101101101011001001110101011000111010011100011110001110000111000111100100100000101100000101001111111011000000010100001111101111000011000000110100101101110101001000111011000100110011111101010000011110111110000100001000101111000101000100111011111100010000010011011110010110001010101011110111010001100011101010110011110101010000111011100100010010101111110111000000100011111111010000000011001011110101010000101110111101001100011011001110010011000110010100100110101100101101001101011011001110110011000101010001111110111000001100011111001110000011001000010011000010110100010100101111101101000011001110110101001100111111001100000101010011111011110000010000111110000100000111111000100000000100000011100000010010000110111000101100100101010101101011101011010001110110111000100100011110110110000100100111100101100001101000011001100110111001100100101000101101011111011010000010010111111110100000001111111111000000000'
			],
		];
	}
}