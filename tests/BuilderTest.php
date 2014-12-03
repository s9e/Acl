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
	* @testdox allow() rejects an empty string used as dimension
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Scope dimensions must have a name
	*/
	public function testScopeDimensionEmpty()
	{
		$builder = new Builder;
		$builder->allow('foo', ['' => 'x']);
	}

	/**
	* @testdox allow() rejects an empty string used as scope value
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Scope value for x cannot be empty
	*/
	public function testScopeValueEmpty()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => '']);
	}

	/**
	* @testdox allow() rejects floats as scope value
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Invalid type for x scope: integer or string expected, double given
	*/
	public function testScopeValueFloat()
	{
		$builder = new Builder;
		$builder->allow('foo', ['x' => 2.2]);
	}

	/**
	* @testdox allow() can be called without a scope
	*/
	public function testAllowNoScope()
	{
		$builder = new Builder;
		$builder->allow('foo');
	}

	/**
	* @testdox deny() can be called without a scope
	*/
	public function testDenyNoScope()
	{
		$builder = new Builder;
		$builder->deny('foo');
	}

	/**
	* @testdox allow() defaults to the global scope if none is provided
	*/
	public function testAllowNoScopeDefaultGlobal()
	{
		$builder = new Builder;
		$builder->allow('foo');
		$this->assertEquals(['foo' => true], $builder->getReaderConfig());
	}

	/**
	* @testdox deny() defaults to the global scope if none is provided
	*/
	public function testDenyNoScopeDefaultGlobal()
	{
		$builder = new Builder;
		$builder->allow('foo');
		$this->assertEquals(['foo' => true], $builder->getReaderConfig());
	}

	/**
	* @testdox addRule() rejects rule "foo"
	* @expectedException InvalidArgumentException
	* @expectedExceptionMessage Unsupported rule 'foo'
	*/
	public function testInvalidRule()
	{
		$builder = new Builder;
		$builder->addRule('src', 'foo', 'trg');
	}

	/**
	* @testdox getReader() returns an instance of s9e\Acl\Reader
	*/
	public function testGetReader()
	{
		$builder = new Builder;
		$this->assertInstanceOf('s9e\\Acl\\Reader', $builder->getReader());
	}

	/**
	* @testdox getReaderConfig() tests
	* @dataProvider getGetReaderConfigTests
	*/
	public function testGetReaderConfig($permissions, $rules, $expected)
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

		$this->assertEquals($expected, $builder->getReaderConfig());
	}

	public function getGetReaderConfigTests()
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