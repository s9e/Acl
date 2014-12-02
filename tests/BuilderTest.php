<?php

namespace s9e\TextFormatter\Tests;

use PHPUnit_Framework_TestCase;
use s9e\Acl\Builder;

/**
* @covers s9e\Acl\Builder
*/
class BuilderTest extends PHPUnit_Framework_TestCase
{
	/**
	* @testdox getAcl() tests
	* @dataProvider getAclTests
	*/
	public function testAcl($permissions, $rules, $expected)
	{
		$builder = new Builder;
		foreach ($permissions as $action => $settings)
		{
			foreach ($settings as $setting)
			{
				list($methodName, $scope) = $setting;
				$builder->$methodName($action, $scope);
			}
		}
		foreach ($rules as $rule)
		{
			list($ruleName, $srcAction, $trgAction) = $rule;
			$builder->addRule($ruleName, $srcAction, $trgAction);
		}

		$this->assertEquals($expected, $builder->getAcl());
	}

	public function getAclTests()
	{
		return [
			[
				['publish' => [['allow', []]]],
				[],
				[
					'publish' => true
				]
			],
			[
				['publish' => [['deny', []]]],
				[],
				[]
			],
			[
				['publish' => [['allow', []], ['deny', []]]],
				[],
				[]
			],
			[
				['publish' => [['allow', ['cat' => 1]]]],
				[],
				[
					'publish' => ["\6", ['publish' => 0], ['cat' => ['' => 1, 1 => 2]]]
				]
			],
		];
	}
}