<?php

namespace s9e\TextFormatter\Tests;

use PHPUnit_Framework_TestCase;
use s9e\Acl\Matrix;

/**
* @covers s9e\Acl\Matrix
*/
class MatrixTest extends PHPUnit_Framework_TestCase
{
	/**
	* @testdox solve() tests
	* @dataProvider getSolveTests
	*/
	public function testSolve($settings, $rules, $expectedOffsets, $expectedBitfields)
	{
		$matrix = new Matrix($settings, $rules);
		$this->assertSame($expectedOffsets, $matrix->getOffsets());
		$this->assertSame($expectedBitfields, $matrix->getBitfields());
	}

	public function getSolveTests()
	{
		return [
			[
				['publish'  => [[Matrix::ALLOW, ['category' => 123]]]],
				[],
				['category' => ['' => 1, 123 => 2]],
				['publish'  => '011']
			],
			[
				['publish'  => [
					[Matrix::ALLOW, ['category' => 123]],
					[Matrix::ALLOW, ['category' => 456]]
				]],
				[],
				['category' => ['' => 1, 123 => 2, 456 => 3]],
				['publish'  => '0111']
			],
			[
				['publish'  => [[Matrix::ALLOW, ['category' => 123, 'type' => 456]]]],
				[],
				[
					'category' => ['' => 1, 123 => 2],
					'type'     => ['' => 3, 456 => 6]
				],
				['publish'  => '000011011']
			],
			[
				['publish'  => [
					[Matrix::ALLOW, ['category' => 123, 'type' => 7]],
					[Matrix::ALLOW, ['category' => 456, 'type' => 8]]
				]],
				[],
				[
					'category' => ['' => 1, 123 => 2, 456 =>  3],
					'type'     => ['' => 4,   7 => 8,   8 => 12]
				],
				['publish'  => '0000011101100101']
			],
		];
	}
}