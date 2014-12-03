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
	* Converts an ACL to a more human-readable representation
	*/
	protected function aclToArray(array $bitfields, array $offsets)
	{
		$arr = [];
		foreach ($bitfields as $action => $bitfield)
		{
			$arr[$action] = $this->bitfieldToArray($bitfield, $offsets);
		}

		return $arr;
	}

	protected function bitfieldToArray($bitfield, array $offsets)
	{
		$arr = [];
		foreach (str_split($bitfield, 1) as $n => $c)
		{
			$scope = [];
			foreach ($offsets as $dimName => $scopeOffsets)
			{
				foreach (array_reverse($scopeOffsets, true) as $scopeValue => $offset)
				{
					if ($n >= $offset)
					{
						$n -= $offset;
						$scope[$dimName] = $scopeValue ?: '*';

						continue 2;
					}
				}
				$scope[$dimName] = 'G';
			}

			$str = '';
			foreach ($scope as $k => $v)
			{
				$str .= $k . '=' . $v . ' ';
			}
			$arr[rtrim($str)] = (int) $c;
		}

		return $arr;
	}

	/**
	* @testdox solve() tests
	* @dataProvider getSolveTests
	*/
	public function testSolve($settings, $rules, $expectedOffsets, $expectedBitfields)
	{
		$matrix = new Matrix($settings, $rules);

		$this->assertEquals(
			$this->aclToArray($expectedBitfields, $expectedOffsets),
			$this->aclToArray($matrix->getBitfields(), $matrix->getOffsets())
		);
		$this->assertSame($expectedOffsets, $matrix->getOffsets());
		$this->assertSame($expectedBitfields, $matrix->getBitfields());
	}

	public function getSolveTests()
	{
		return [
			[
				['publish'  => [[['category' => 123], Matrix::ALLOW]]],
				[],
				['category' => ['' => 1, 123 => 2]],
				['publish'  => '011']
			],
			[
				['publish'  => [
					[['category' => 123], Matrix::ALLOW],
					[['category' => 456], Matrix::ALLOW]
				]],
				[],
				['category' => ['' => 1, 123 => 2, 456 => 3]],
				['publish'  => '0111']
			],
			[
				['publish'  => [[['category' => 123, 'type' => 456], Matrix::ALLOW]]],
				[],
				[
					'category' => ['' => 1, 123 => 2],
					'type'     => ['' => 3, 456 => 6]
				],
				['publish'  => '000011011']
			],
			[
				['publish'  => [
					[['category' => 123, 'type' => 7], Matrix::ALLOW],
					[['category' => 456, 'type' => 8], Matrix::ALLOW]
				]],
				[],
				[
					'category' => ['' => 1, 123 => 2, 456 =>  3],
					'type'     => ['' => 4,   7 => 8,   8 => 12]
				],
				['publish'  => '0000011101100101']
			],
			[
				['publish'  => [
					[['category' => 123, 'type' => 7], Matrix::DENY ],
					[[],                               Matrix::ALLOW]
				]],
				[],
				[
					'category' => ['' => 1, 123 => 2],
					'type'     => ['' => 3,   7 => 6]
				],
				['publish'  => '111111110']
			],
		];
	}
}